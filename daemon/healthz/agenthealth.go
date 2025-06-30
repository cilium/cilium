// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/status"
)

var agentHealthzCell = cell.Module(
	"agent-healthz",
	"Cilium Agent Healthz endpoint",

	cell.Invoke(registerAgentHealthHTTPService),
)

type agentHealthParams struct {
	cell.In

	Logger   *slog.Logger
	JobGroup job.Group

	StatusCollector status.StatusCollector
}

// registerAgentHealthHTTPService registers a handler function for the /healthz status HTTP endpoint
// exposed on localhost (127.0.0.1 and/or ::1, depending on IPv4/IPv6 options). This
// endpoint reports the agent health status and is equivalent to what the `cilium status --brief`
// CLI tool reports.
func registerAgentHealthHTTPService(params agentHealthParams) error {
	hosts := map[string]string{}
	if option.Config.EnableIPv4 {
		hosts["ipv4"] = "127.0.0.1"
	}
	if option.Config.EnableIPv6 {
		hosts["ipv6"] = "::1"
	}

	handler := &agentHealthHandler{
		logger:          params.Logger,
		statusCollector: params.StatusCollector,
	}

	mux := http.NewServeMux()
	mux.Handle("/healthz", handler)

	available := len(hosts)
	for name, host := range hosts {
		params.JobGroup.Add(job.OneShot(fmt.Sprintf("agent-healthz-server-%s", name), func(ctx context.Context, health cell.Health) error {
			lc := net.ListenConfig{Control: setsockoptReuseAddrAndPort}
			addr := net.JoinHostPort(host, fmt.Sprintf("%d", option.Config.AgentHealthPort))
			ln, err := lc.Listen(context.Background(), "tcp", addr)
			if errors.Is(err, unix.EADDRNOTAVAIL) {
				params.Logger.Info("healthz status API server not available", logfields.Address, addr)
				return fmt.Errorf("healthz status API server not available: %w", err)
			} else if err != nil {
				params.Logger.Error("Unable to start healthz status API server",
					logfields.Address, addr,
					logfields.Error, err,
				)
				return fmt.Errorf("failed to start healthz status API server: %w", err)
			}

			srv := &http.Server{
				Addr:    addr,
				Handler: mux,
			}

			go func() {
				<-ctx.Done()
				srv.Shutdown(context.Background()) // does not use job context, as it has already been closed!
			}()

			params.Logger.Info("Starting healthz status API server", logfields.Address, addr)
			if err := srv.Serve(ln); errors.Is(err, http.ErrServerClosed) {
				params.Logger.Info("healthz status API server shutdown", logfields.Address, addr)
			} else if err != nil {
				params.Logger.Error("Error serving healthz status API server",
					logfields.Address, addr,
					logfields.Error, err,
				)
				return fmt.Errorf("failed to start healthz status API server: %w", err)
			}

			return nil
		}))
	}

	if available <= 0 {
		return fmt.Errorf("no healthz status API server started")
	}

	return nil
}

type agentHealthHandler struct {
	logger          *slog.Logger
	statusCollector status.StatusCollector
}

func (h *agentHealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requireK8sConnectivity := option.Config.AgentHealthRequireK8sConnectivity
	if v := r.Header.Get("require-k8s-connectivity"); v != "" {
		res, err := strconv.ParseBool(v)
		if err != nil {
			h.logger.Warn("require-k8s-connectivity should be bool",
				logfields.Value, v,
				logfields.Error, err,
			)
		} else {
			requireK8sConnectivity = res
		}
	}
	isUnhealthy := func(sr *models.StatusResponse) bool {
		if sr.Cilium != nil {
			state := sr.Cilium.State
			return state != models.StatusStateOk && state != models.StatusStateDisabled
		}
		return false
	}
	statusCode := http.StatusOK
	sr := h.statusCollector.GetStatus(true, requireK8sConnectivity)
	if isUnhealthy(&sr) {
		h.logger.Info("/healthz returning unhealthy",
			logfields.State, sr.Cilium.State,
			logfields.Error, errors.New(sr.Cilium.Msg),
		)
		statusCode = http.StatusServiceUnavailable
	}

	w.WriteHeader(statusCode)
}
