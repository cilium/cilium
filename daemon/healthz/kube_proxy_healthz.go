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

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/loadbalancer/legacy/service"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/status"
	"github.com/cilium/cilium/pkg/time"
)

// ServiceInterface to help with testing.
type ServiceInterface interface {
	GetLastUpdatedTs() time.Time
	GetCurrentTs() time.Time
}

type kubeproxyHealthzHandler struct {
	statusCollector status.StatusCollector
	svc             ServiceInterface
}

var kubeProxyHealthzCell = cell.Module(
	"kube-proxy-healthz",
	"Kube-Proxy Healthz endpoint",

	cell.Invoke(registerKubeProxyHealthzHTTPService),
	cell.Config(config{
		KubeProxyReplacementHealthzBindAddress: "",
	}),
)

type kubeProxyHealthParams struct {
	cell.In

	Logger   *slog.Logger
	JobGroup job.Group

	AgentConfig     *option.DaemonConfig
	Config          config
	StatusCollector status.StatusCollector
	ServiceManager  service.ServiceManager
}

type config struct {
	KubeProxyReplacementHealthzBindAddress string
}

func (r config) Flags(flags *pflag.FlagSet) {
	flags.String("kube-proxy-replacement-healthz-bind-address", r.KubeProxyReplacementHealthzBindAddress, "The IP address with port for kube-proxy replacement health check server to serve on (set to '0.0.0.0:10256' for all IPv4 interfaces and '[::]:10256' for all IPv6 interfaces). Set empty to disable.")
}

// registerKubeProxyHealthzHTTPService registers a handler function for the kube-proxy /healthz
// status HTTP endpoint exposed on addr.
// This endpoint reports the agent health status with the timestamp.
func registerKubeProxyHealthzHTTPService(params kubeProxyHealthParams) error {
	if params.Config.KubeProxyReplacementHealthzBindAddress == "" || params.AgentConfig.KubeProxyReplacement == option.KubeProxyReplacementFalse {
		return nil
	}

	params.JobGroup.Add(job.OneShot("kube-proxy-healthz-server", func(ctx context.Context, health cell.Health) error {
		addr := params.Config.KubeProxyReplacementHealthzBindAddress
		lc := net.ListenConfig{Control: setsockoptReuseAddrAndPort}
		ln, err := lc.Listen(context.Background(), "tcp", addr)
		if errors.Is(err, unix.EADDRNOTAVAIL) {
			params.Logger.Info("KubeProxy healthz server not available", logfields.Address, addr)
		} else if err != nil {
			params.Logger.Error("hint: kube-proxy should not be running nor listening on the same healthz-bind-address.",
				logfields.Address, addr,
				logfields.Error, err,
			)
			return fmt.Errorf("failed to start kubeproxy healthz server: %w", err)
		}

		mux := http.NewServeMux()
		mux.Handle("/healthz", kubeproxyHealthzHandler{statusCollector: params.StatusCollector, svc: params.ServiceManager})

		srv := &http.Server{
			Addr:    addr,
			Handler: mux,
		}

		params.Logger.Info("Starting kube-proxy healthz server", logfields.Address, addr)

		if err := srv.Serve(ln); errors.Is(err, http.ErrServerClosed) {
			params.Logger.Info("kube-proxy healthz status API server shutdown", logfields.Address, addr)
		} else if err != nil {
			params.Logger.Error("Unable to start kube-proxy healthz server",
				logfields.Address, addr,
				logfields.Error, err,
			)
			return fmt.Errorf("failed to start kube-proxy healthz server: %w", err)
		}

		return nil
	}))

	return nil
}

func (h kubeproxyHealthzHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	isUnhealthy := func(sr *models.StatusResponse) bool {
		if sr.Cilium != nil {
			state := sr.Cilium.State
			return state != models.StatusStateOk && state != models.StatusStateDisabled
		}
		return false
	}

	statusCode := http.StatusOK
	currentTs := h.svc.GetCurrentTs()
	lastUpdateTs := currentTs
	// We piggy back here on Cilium daemon health. If Cilium is healthy, we can
	// reasonably assume that the node networking is ready.
	sr := h.statusCollector.GetStatus(true, true)
	if isUnhealthy(&sr) {
		statusCode = http.StatusServiceUnavailable
		lastUpdateTs = h.svc.GetLastUpdatedTs()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, `{"lastUpdated": %q,"currentTime": %q}`, lastUpdateTs, currentTs)
}
