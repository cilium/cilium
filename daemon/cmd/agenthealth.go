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
	"net"
	"net/http"
	"syscall"

	"github.com/cilium/cilium/api/v1/models"

	"golang.org/x/sys/unix"
)

func setsockoptReuseAddrAndPort(network, address string, c syscall.RawConn) error {
	var soerr error
	if err := c.Control(func(su uintptr) {
		s := int(su)
		// Allow reuse of recently-used addresses. This socket option is
		// set by default on listeners in Go's net package, see
		// net setDefaultListenerSockopts
		soerr = unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
		if soerr != nil {
			return
		}
		// Allow reuse of recently-used ports. This gives the agent a
		// better change to re-bind upon restarts.
		soerr = unix.SetsockoptInt(s, unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return soerr
}

// startAgentHealthHTTPService registers a handler function for the /healthz
// status HTTP endpoint exposed on addr. This endpoint reports the agent health
// status and is equivalent to what the `cilium status --brief` CLI tool reports.
func (d *Daemon) startAgentHealthHTTPService(addr string) {
	lc := net.ListenConfig{Control: setsockoptReuseAddrAndPort}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		log.WithError(err).Fatalf("Unable to listen on %s for healthz status API server", addr)
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
			statusCode = http.StatusInternalServerError
		}
		w.WriteHeader(statusCode)
	}))
	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		err := srv.Serve(ln)
		if err == http.ErrServerClosed {
			log.Info("healthz status API server shutdown")
		} else if err != nil {
			log.WithError(err).Fatal("Unable to start healthz status API server")
		}
	}()
	log.Infof("Started healthz status API server on address %s", addr)
}
