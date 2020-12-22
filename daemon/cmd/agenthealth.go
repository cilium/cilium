// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
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
