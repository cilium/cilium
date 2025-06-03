// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// Cell implements the support for the HealthCheckNodePort field.
// For each service that has HealthCheckNodePort set to a non-zero value it
// starts an HTTP server on that port and responds with the number of active
// node-local backends. This allows external load-balancers to avoid directing
// traffic to services that have no available backends.
var Cell = cell.Module(
	"loadbalancer-healthserver",
	"Serves service health status to external load-balancers",

	cell.Invoke(registerHealthServer),
)

type healthServerParams struct {
	cell.In

	Jobs          job.Group
	Log           *slog.Logger
	DB            *statedb.DB
	Config        lb.Config
	TestConfig    *lb.TestConfig `optional:"true"`
	ExtConfig     lb.ExternalConfig
	Frontends     statedb.Table[*lb.Frontend]
	Backends      statedb.Table[*lb.Backend]
	Writer        *writer.Writer
	NodeAddresses statedb.Table[tables.NodeAddress]
}

// healthServer manages HTTP health check ports. For each added service,
// it opens a HTTP server on the specified HealthCheckNodePort and either
// responds with 200 OK if there are local endpoints for the service, or with
// 503 Service Unavailable if the service does not have any local endpoints.
type healthServer struct {
	params           healthServerParams
	serverByPort     map[uint16]*httpHealthServer
	portByService    map[lb.ServiceName]uint16
	nodeName         string
	healthServerAddr *cmtypes.AddrCluster
}

func registerHealthServer(params healthServerParams) {
	if !params.Config.EnableExperimentalLB {
		return
	}

	s := &healthServer{
		params:        params,
		serverByPort:  map[uint16]*httpHealthServer{},
		portByService: map[lb.ServiceName]uint16{},
	}

	if params.TestConfig != nil {
		addr := ChooseHealthServerLoopbackAddressForTesting()
		addrCluster := cmtypes.AddrClusterFrom(addr, 0)
		s.healthServerAddr = &addrCluster
	}

	params.Jobs.Add(job.OneShot("control-loop", s.controlLoop))
}

func ChooseHealthServerLoopbackAddressForTesting() netip.Addr {
	// Choose a loopback IP address that's tied to the process ID.
	// This makes it possible to stress test the health server in parallel
	// as each process gets its own address.
	pid := os.Getpid()
	return netip.AddrFrom4(
		[4]byte{
			127,
			1 | byte(pid>>16&0xff),
			byte(pid >> 8 & 0xff),
			1 | byte(pid&0xff),
		},
	)
}

func (s *healthServer) controlLoop(ctx context.Context, health cell.Health) error {
	extCfg := s.params.ExtConfig
	if !extCfg.KubeProxyReplacement || !s.params.Config.EnableHealthCheckNodePort {
		return nil
	}

	s.nodeName = nodeTypes.GetName()

	// Watch services for changes to add and remove the listeners.
	wtxn := s.params.DB.WriteTxn(s.params.Frontends)
	frontendChanges, err := s.params.Frontends.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}

	// Limit the rate at which the change batches are processed.
	limiter := rate.NewLimiter(100*time.Millisecond, 1)
	defer limiter.Stop()

	defer s.cleanupListeners(ctx)

	for {
		if err := limiter.Wait(ctx); err != nil {
			return err
		}

		changes, watch := frontendChanges.Next(s.params.DB.ReadTxn())
		for change := range changes {
			fe := change.Object
			if (fe.Type != lb.SVCTypeLoadBalancer && fe.Type != lb.SVCTypeNodePort) ||
				fe.Address.Scope == lb.ScopeInternal {
				continue
			}

			svc := fe.Service
			name := svc.Name
			port := svc.HealthCheckNodePort

			// Health server is only for LoadBalancer services with a local
			// traffic policy.
			needsServer := !change.Deleted &&
				port > 0 &&
				svc.ExtTrafficPolicy == lb.SVCTrafficPolicyLocal

			// Check if a health checker server exists already for this service and remove it if port has changed
			// or if the service is no longer applicable.
			// NOTE: A complication here is that we may have both a NodePort and a LoadBalancer frontend and
			// we will process both here. We may see the NodePort first and create the listener and then we'll
			// see the LoadBalancer and create the Frontend for providing access to the health server using the
			// LoadBalancer VIP.
			oldPort, exists := s.portByService[name]
			if exists && (oldPort != port || !needsServer) {
				s.removeListener(ctx, oldPort)
				delete(s.portByService, name)
				exists = false
			}

			if !exists && needsServer {
				s.addListener(svc, port)
				s.portByService[name] = port
			}

			if fe.Type == lb.SVCTypeLoadBalancer {
				healthServiceName := name.AppendSuffix(":healthserver")
				if !needsServer {
					wtxn := s.params.Writer.WriteTxn()
					s.params.Writer.DeleteBackendsOfService(wtxn, healthServiceName, source.Local)
					s.params.Writer.DeleteServiceAndFrontends(wtxn, healthServiceName)
					wtxn.Commit()
				} else if extCfg.EnableHealthCheckLoadBalancerIP {
					// Create a LoadBalancer service to expose the health server on the $LB_VIP.
					// For NodePort we don't need anything as the HealthServer is already listening on
					// all node addresses.
					wtxn := s.params.Writer.WriteTxn()
					s.params.Writer.UpsertServiceAndFrontends(
						wtxn,
						&lb.Service{
							Name:             healthServiceName,
							Source:           source.Local,
							ExtTrafficPolicy: lb.SVCTrafficPolicyLocal,
							IntTrafficPolicy: lb.SVCTrafficPolicyLocal,
						},
						lb.FrontendParams{
							Address: lb.L3n4Addr{
								AddrCluster: fe.Address.AddrCluster,
								L4Addr: lb.L4Addr{
									Protocol: lb.TCP,
									Port:     port,
								},
								Scope: lb.ScopeExternal,
							},
							Type:        lb.SVCTypeLoadBalancer,
							ServiceName: healthServiceName,
							ServicePort: port,
						},
					)

					// Find NodePort addr to use as a backend for $LB_VIP:$HC_NODEPORT frontend.
					beAddr := netip.IPv4Unspecified()
					is4 := fe.Address.AddrCluster.Is4()
					if !is4 {
						beAddr = netip.IPv6Unspecified()
					}
					for addr := range s.params.NodeAddresses.List(wtxn, tables.NodeAddressNodePortIndex.Query(true)) {
						if is4 && addr.Addr.Is4() {
							beAddr = addr.Addr
							break
						} else if !is4 && addr.Addr.Is6() {
							beAddr = addr.Addr
							break
						}
					}

					s.params.Writer.SetBackends(
						wtxn,
						healthServiceName,
						source.Local,
						lb.BackendParams{
							Address: lb.L3n4Addr{
								AddrCluster: cmtypes.AddrClusterFrom(beAddr, 0),
								L4Addr: lb.L4Addr{
									Protocol: lb.TCP,
									Port:     port,
								},
								Scope: lb.ScopeInternal,
							},
							NodeName: s.nodeName,
							State:    lb.BackendStateActive,
						},
					)
					wtxn.Commit()
				}
			}
		}
		health.OK(fmt.Sprintf("%d health servers running", len(s.serverByPort)))

		select {
		case <-ctx.Done():
			return nil
		case <-watch:
		}
	}
}

func (s *healthServer) cleanupListeners(ctx context.Context) {
	for _, srv := range s.serverByPort {
		srv.shutdown(ctx)
	}
}

func (s *healthServer) addListener(svc *lb.Service, port uint16) {
	if srv, exists := s.serverByPort[port]; exists {
		s.params.Log.Warn("HealthServer: Listener already exists",
			logfields.Port, port,
			logfields.New, svc.Name,
			logfields.Old, srv.name,
		)
		return
	}

	srv := &httpHealthServer{
		nodeName: s.nodeName,
		name:     svc.Name,
		svc:      svc,
		db:       s.params.DB,
		backends: s.params.Backends,
	}
	bindAddr := fmt.Sprintf(":%d", port)
	if s.healthServerAddr != nil {
		bindAddr = s.healthServerAddr.Addr().String() + bindAddr
	}
	srv.Server = http.Server{
		Addr:    bindAddr,
		Handler: srv,
	}
	s.params.Jobs.Add(
		job.OneShot(
			fmt.Sprintf("listener-%d", port),
			func(ctx context.Context, health cell.Health) error {
				if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
					return err
				}
				return nil
			},
			job.WithRetry(-1, &job.ExponentialBackoff{
				Min: 200 * time.Millisecond,
				Max: 10 * time.Second,
			}),
		),
	)
	s.serverByPort[port] = srv
}

func (s *healthServer) removeListener(ctx context.Context, port uint16) {
	if srv, ok := s.serverByPort[port]; ok {
		srv.shutdown(ctx)
		delete(s.serverByPort, port)
	}
}

type healthResponseServiceName struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// healthResponse represents the object returned by the health server
type healthResponse struct {
	Service        healthResponseServiceName `json:"service"`
	LocalEndpoints int                       `json:"localEndpoints"`
}

type httpHealthServer struct {
	http.Server

	nodeName string
	name     lb.ServiceName
	svc      *lb.Service
	db       *statedb.DB
	backends statedb.Table[*lb.Backend]
}

func (h *httpHealthServer) getLocalEndpointCount() int {
	if h.svc.ProxyRedirect != nil {
		// Traffic is redirected to a proxy and thus we have no information on
		// the actual backends. Return a synthetic single backend in this case.
		return 1
	}

	txn := h.db.ReadTxn()

	// Gather the backends for the service.
	activeCount := 0
	for be := range h.backends.List(txn, lb.BackendByServiceName(h.name)) {
		inst := be.GetInstance(h.name)
		if inst.NodeName != "" && inst.NodeName != h.nodeName {
			// Skip non-local backends.
			continue
		}
		if inst.State == lb.BackendStateActive {
			activeCount++
		}
	}
	return activeCount
}

func (h *httpHealthServer) shutdown(ctx context.Context) {
	h.Server.Shutdown(ctx)
}

func (h *httpHealthServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Use headers and JSON output compatible with kube-proxy
	response := healthResponse{
		Service:        healthResponseServiceName{Namespace: h.name.Namespace, Name: h.name.Name},
		LocalEndpoints: h.getLocalEndpointCount(),
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Load-Balancing-Endpoint-Weight", strconv.Itoa(response.LocalEndpoints))

	if response.LocalEndpoints == 0 {
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
