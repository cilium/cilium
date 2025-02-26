// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"

	"github.com/cilium/cilium/pkg/logging"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// startAgentHealthHTTPService registers a handler function for the /healthz status HTTP endpoint
// exposed on localhost (127.0.0.1 and/or ::1, depending on IPv4/IPv6 options). This
// endpoint reports the agent health status and is equivalent to what the `cilium status --brief`
// CLI tool reports.
func (d *Daemon) startAgentHealthHTTPService() {
	var hosts []string
	if option.Config.EnableIPv4 {
		hosts = append(hosts, "127.0.0.1")
	}
	if option.Config.EnableIPv6 {
		hosts = append(hosts, "::1")
	}

	mux := http.NewServeMux()
	mux.Handle("/healthz", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireK8sConnectivity := true
		if v := r.Header.Get("require-k8s-connectivity"); v != "" {
			res, err := strconv.ParseBool(v)
			if err != nil {
				d.logger.Warn(
					"require-k8s-connectivity should be bool",
					slog.String("value", v),
					slog.Any(logfields.Error, err),
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
		sr := d.getStatus(true, requireK8sConnectivity)
		if isUnhealthy(&sr) {
			d.logger.Warn("/healthz returning unhealthy",
				slog.Any(logfields.Error, sr.Cilium.Msg),
				slog.String(logfields.State, sr.Cilium.State),
			)
			statusCode = http.StatusServiceUnavailable
		}

		w.WriteHeader(statusCode)
	}))

	available := len(hosts)
	for _, host := range hosts {
		lc := net.ListenConfig{Control: setsockoptReuseAddrAndPort}
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", option.Config.AgentHealthPort))
		addrField := slog.String("address", addr)
		ln, err := lc.Listen(context.Background(), "tcp", addr)
		if errors.Is(err, unix.EADDRNOTAVAIL) {
			d.logger.Info(
				"healthz status API server not available",
				addrField,
			)
			available--
			continue
		} else if err != nil {
			logging.Fatal(
				d.logger,
				"Unable to start healthz status API server",
				slog.Any(logfields.Error, err),
				addrField,
			)
		}

		go func(addr string, ln net.Listener) {
			srv := &http.Server{
				Addr:    addr,
				Handler: mux,
			}
			err := srv.Serve(ln)
			if errors.Is(err, http.ErrServerClosed) {
				d.logger.Info(
					"healthz status API server shutdown",
					addrField,
				)
			} else if err != nil {
				logging.Fatal(
					d.logger,
					"Error serving healthz status API server",
					addrField,
					slog.Any(logfields.Error, err),
				)
			}
		}(addr, ln)
		d.logger.Info(
			"Started healthz status API server",
			addrField,
		)
	}

	if available <= 0 {
		logging.Fatal(
			d.logger,
			"No healthz status API server started",
			slog.Any("hosts", hosts),
		)
	}
}
