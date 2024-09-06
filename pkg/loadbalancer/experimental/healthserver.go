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
	"strconv"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/rate"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
)

// healthServerCell implements the support for the HealthCheckNodePort field.
// For each service that has HealthCheckNodePort set to a non-zero value it
// starts an HTTP server on that port and responds with the number of active
// backends. This allows external load-balancers to avoid directing traffic
// to services that have no available backends.
var healthServerCell = cell.Module(
	"healthserver",
	"Serves NodePort health status to external load-balancers",
	cell.Invoke(registerHealthServer),
)

type healthServerParams struct {
	cell.In

	Jobs         job.Group
	Log          *slog.Logger
	DB           *statedb.DB
	DaemonConfig *option.DaemonConfig
	Services     statedb.Table[*Service]
	Backends     statedb.Table[*Backend]
}

// healthServer manages HTTP health check ports. For each added service,
// it opens a HTTP server on the specified HealthCheckNodePort and either
// responds with 200 OK if there are local endpoints for the service, or with
// 503 Service Unavailable if the service does not have any local endpoints.
type healthServer struct {
	params        healthServerParams
	serverByPort  map[uint16]*httpHealthServer
	portByService map[lb.ServiceName]uint16
}

func registerHealthServer(params healthServerParams) {
	if !params.DaemonConfig.EnableHealthCheckNodePort {
		return
	}

	s := &healthServer{
		params:        params,
		serverByPort:  map[uint16]*httpHealthServer{},
		portByService: map[lb.ServiceName]uint16{},
	}
	params.Jobs.Add(job.OneShot("control-loop", s.controlLoop))
}

func (s *healthServer) controlLoop(ctx context.Context, health cell.Health) error {
	// Watch services for changes to add and remove the listeners.
	wtxn := s.params.DB.WriteTxn(s.params.Services)
	serviceChanges, err := s.params.Services.Changes(wtxn)
	wtxn.Commit()
	if err != nil {
		return err
	}
	defer serviceChanges.Close()

	// Limit the rate at which the change batches are processed.
	limiter := rate.NewLimiter(100*time.Millisecond, 1)

	for {
		for change, _, ok := serviceChanges.Next(); ok; change, _, ok = serviceChanges.Next() {
			svc := change.Object
			name := svc.Name
			port := svc.HealthCheckNodePort

			if change.Deleted {
				if port, ok := s.portByService[name]; ok {
					s.removeListener(ctx, port)
					delete(s.portByService, name)
				}
			} else {
				oldPort, found := s.portByService[name]
				if found && oldPort != port {
					// HealthCheckNodePort has changed, we treat this as a DeleteService
					// followed by an Insert.
					s.removeListener(ctx, oldPort)
					delete(s.portByService, name)
					found = false
				}
				if port == 0 || found {
					continue
				}
				s.serverByPort[port] = s.addListener(name, port)
				s.portByService[name] = port
			}
		}
		health.OK(fmt.Sprintf("%d health servers running", len(s.serverByPort)))

		select {
		case <-ctx.Done():
		case <-serviceChanges.Watch(s.params.DB.ReadTxn()):
		}

		if err := limiter.Wait(ctx); err != nil {
			return err
		}
	}
}

func (s *healthServer) addListener(name lb.ServiceName, port uint16) *httpHealthServer {
	srv := &httpHealthServer{
		name:     name,
		db:       s.params.DB,
		backends: s.params.Backends,
	}
	srv.Server = http.Server{
		Addr:    fmt.Sprintf(":%d", port),
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
			}))
	return srv
}

func (s *healthServer) removeListener(ctx context.Context, port uint16) {
	if srv, ok := s.serverByPort[port]; ok {
		srv.shutdown(ctx)
		delete(s.serverByPort, port)
	}
}

type serviceName struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// healthResponse represents the object returned by the health server
type healthResponse struct {
	Service        serviceName `json:"service"`
	LocalEndpoints int         `json:"localEndpoints"`
}

type httpHealthServer struct {
	http.Server

	name     lb.ServiceName
	db       *statedb.DB
	backends statedb.Table[*Backend]
}

func (h *httpHealthServer) getLocalEndpointCount() int {
	txn := h.db.ReadTxn()

	activeCount := 0
	backends := h.backends.List(txn, BackendByServiceName(h.name))
	for be, _, ok := backends.Next(); ok; be, _, ok = backends.Next() {
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
		Service:        serviceName{Namespace: h.name.Namespace, Name: h.name.Name},
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
