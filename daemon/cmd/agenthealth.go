// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
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
		isUnhealthy := func(sr *models.StatusResponse) bool {
			if sr.Cilium != nil {
				state := sr.Cilium.State
				return state != models.StatusStateOk && state != models.StatusStateDisabled
			}
			return false
		}
		statusCode := http.StatusOK
		sr := d.getStatus(true)
		if isUnhealthy(&sr) {
			statusCode = http.StatusServiceUnavailable
		}

		w.WriteHeader(statusCode)
	}))

	available := len(hosts)
	for _, host := range hosts {
		lc := net.ListenConfig{Control: setsockoptReuseAddrAndPort}
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", option.Config.AgentHealthPort))
		addrField := logrus.Fields{"address": addr}
		ln, err := lc.Listen(context.Background(), "tcp", addr)
		if errors.Is(err, unix.EADDRNOTAVAIL) {
			log.WithFields(addrField).Info("healthz status API server not available")
			available--
			continue
		} else if err != nil {
			log.WithFields(addrField).WithError(err).Fatal("Unable to start healthz status API server")
		}

		go func(addr string, ln net.Listener) {
			srv := &http.Server{
				Addr:    addr,
				Handler: mux,
			}
			err := srv.Serve(ln)
			if errors.Is(err, http.ErrServerClosed) {
				log.WithFields(addrField).Info("healthz status API server shutdown")
			} else if err != nil {
				log.WithFields(addrField).WithError(err).Fatal("Error serving healthz status API server")
			}
		}(addr, ln)
		log.WithFields(addrField).Info("Started healthz status API server")
	}

	if available <= 0 {
		log.WithField("hosts", hosts).Fatal("No healthz status API server started")
	}
}
