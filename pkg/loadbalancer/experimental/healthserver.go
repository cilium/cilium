// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package experimental

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
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

// healthServerCell implements the support for the HealthCheckNodePort field.
// For each service that has HealthCheckNodePort set to a non-zero value it
// starts an HTTP server on that port and responds with the number of active
// node-local backends. This allows external load-balancers to avoid directing
// traffic to services that have no available backends.
var healthServerCell = cell.Module(
	"healthserver",
	"Serves service health status to external load-balancers",
	cell.Invoke(registerHealthServer),
)

type healthServerParams struct {
	cell.In

	Jobs       job.Group
	Log        *slog.Logger
	DB         *statedb.DB
	Config     Config
	TestConfig *TestConfig `optional:"true"`
	ExtConfig  ExternalConfig
	Frontends  statedb.Table[*Frontend]
	Backends   statedb.Table[*Backend]
	Writer     *Writer
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
	healthServerAddr cmtypes.AddrCluster
}

func registerHealthServer(params healthServerParams) {
	if !params.Config.EnableExperimentalLB || !params.ExtConfig.EnableHealthCheckNodePort {
		return
	}

	s := &healthServer{
		params:        params,
		serverByPort:  map[uint16]*httpHealthServer{},
		portByService: map[lb.ServiceName]uint16{},
	}

	addr := netip.IPv4Unspecified()
	if params.TestConfig != nil {
		addr = chooseHealthServerLoopbackAddressForTesting()
	}
	s.healthServerAddr = cmtypes.AddrClusterFrom(addr, 0)

	params.Jobs.Add(job.OneShot("control-loop", s.controlLoop))
}

func chooseHealthServerLoopbackAddressForTesting() netip.Addr {
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

	defer s.cleanupListeners(ctx)

	for {
		if err := limiter.Wait(ctx); err != nil {
			return err
		}

		changes, watch := frontendChanges.Next(s.params.DB.ReadTxn())
		for change := range changes {
			fe := change.Object
			if fe.Type != lb.SVCTypeLoadBalancer {
				continue
			}

			svc := fe.service
			name := svc.Name
			healthServiceName := name.AppendSuffix("-healthserver")
			port := svc.HealthCheckNodePort

			// Health server is only for LoadBalancer services with a local
			// traffic policy.
			needsServer := !change.Deleted &&
				port > 0 &&
				svc.ExtTrafficPolicy == lb.SVCTrafficPolicyLocal

			// Check if a health checker server exists already for this service and remove it if port has changed
			// or if the service is no longer applicable.
			oldPort, exists := s.portByService[name]
			if exists && (oldPort != port || !needsServer) {
				s.removeListener(ctx, oldPort)
				delete(s.portByService, name)
				exists = false
				wtxn := s.params.Writer.WriteTxn()
				s.params.Writer.DeleteServiceAndFrontends(
					wtxn,
					healthServiceName,
				)
				wtxn.Commit()
			}

			if !needsServer || exists {
				continue
			}

			s.serverByPort[port] = s.addListener(svc, port)
			s.portByService[name] = port

			// Create a NodePort service to expose the health server.
			wtxn := s.params.Writer.WriteTxn()
			s.params.Writer.UpsertServiceAndFrontends(
				wtxn,
				&Service{
					Name:             healthServiceName,
					Source:           source.Local,
					ExtTrafficPolicy: lb.SVCTrafficPolicyLocal,
					IntTrafficPolicy: lb.SVCTrafficPolicyLocal,
				},
				FrontendParams{
					Address: lb.L3n4Addr{
						AddrCluster: fe.Address.AddrCluster,
						L4Addr: lb.L4Addr{
							Protocol: lb.TCP,
							Port:     port,
						},
						Scope: lb.ScopeExternal,
					},
					Type:        fe.Type,
					ServiceName: healthServiceName,
					ServicePort: port,
				},
			)
			s.params.Writer.UpsertBackends(
				wtxn,
				healthServiceName,
				source.Local,
				BackendParams{
					L3n4Addr: lb.L3n4Addr{
						AddrCluster: s.healthServerAddr,
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

func (s *healthServer) addListener(svc *Service, port uint16) *httpHealthServer {
	srv := &httpHealthServer{
		nodeName: s.nodeName,
		name:     svc.Name,
		svc:      svc,
		db:       s.params.DB,
		backends: s.params.Backends,
	}
	srv.Server = http.Server{
		Addr:    fmt.Sprintf("%s:%d", s.healthServerAddr.Addr().String(), port),
		Handler: srv,
	}
	s.params.Jobs.Add(
		job.OneShot(
			fmt.Sprintf("listener-%d", port),
			func(ctx context.Context, health cell.Health) error {
				if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
					fmt.Printf(">>> ListenAndServe: %s\n", err)
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

	return srv
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
	svc      *Service
	db       *statedb.DB
	backends statedb.Table[*Backend]
}

func (h *httpHealthServer) getLocalEndpointCount() int {
	if h.svc.ProxyRedirect != nil {
		// Traffic is redirected to a proxy and thus we have no information on
		// the actual backends. Return a synthetic single backend in this case.
		return 1
	}

	txn := h.db.ReadTxn()

	// Gather the backends. Since the service has traffic policy set to local the
	// backends we find here are node local.
	activeCount := 0
	for be := range h.backends.List(txn, BackendByServiceName(h.name)) {
		if be.State == lb.BackendStateActive {
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
