// Copyright 2019 Authors of Cilium
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

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"syscall"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
	"golang.org/x/sys/unix"
)

// startServer starts an api server listening on the given address.
func startServer(shutdownSignal <-chan struct{}, allSystemsGo <-chan struct{}, addrs ...string) {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		select {
		// only start serving the real health check once all systems all up and running
		case <-allSystemsGo:
			healthHandler(w, r)
		default:
			healthHandlerOK(w, r)
		}
	})

	errs := make(chan error, 1)
	nServers := 0

	// Since we are opening this on localhost only, we need to make sure
	// we can open for both v4 and v6 localhost. In case the user is running
	// v4-only or v6-only.
	for _, addr := range addrs {
		if addr == "" {
			continue
		}
		nServers++
		srv := &http.Server{Addr: addr}
		errCh := make(chan error, 1)

		lc := net.ListenConfig{Control: setsockoptReuseAddrAndPort}
		ln, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			log.WithError(err).Fatalf("Unable to listen on %s for healthz apiserver", addr)
		}

		go func() {
			err := srv.Serve(ln)
			if err != nil {
				errCh <- err
				errs <- err
			}
		}()
		go func() {
			select {
			case <-shutdownSignal:
				if err := srv.Shutdown(context.Background()); err != nil {
					log.WithError(err).Error("apiserver shutdown")
				}
			case err := <-errCh:
				log.WithError(err).Warn("Unable to start status api")
			}
		}()
		log.Infof("Starting apiserver on address %s", addr)
	}

	for err := range errs {
		nServers--
		if nServers == 0 {
			log.WithError(err).Fatal("Unable to start status api")
		}
	}
}

func healthHandlerOK(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("ok")); err != nil {
		log.WithError(err).Error("Failed to write liveness-probe response")
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	statusCode := http.StatusOK
	reply := "ok"

	if err := checkStatus(); err != nil {
		statusCode = http.StatusInternalServerError
		reply = err.Error()
		log.WithError(err).Warn("Health check status")
	}

	w.WriteHeader(statusCode)
	if _, err := w.Write([]byte(reply)); err != nil {
		log.WithError(err).Error("Failed to write liveness-probe response")
	}
}

// checkStatus checks the connection status to the kvstore and
// k8s apiserver and returns an error if any of them is unhealthy
func checkStatus() error {
	if kvstoreEnabled() {
		// We check if we are the leader here because only the leader has
		// access to the kvstore client. Otherwise, the kvstore client check
		// will block. It is safe for a non-leader to skip this check, as the
		// it is the leader's responsibility to report the status of the
		// kvstore client.
		if leader, ok := isLeader.Load().(bool); ok && leader {
			if client := kvstore.Client(); client == nil {
				return fmt.Errorf("kvstore client not configured")
			} else if _, err := client.Status(); err != nil {
				return err
			}
		}
	}

	if _, err := k8s.Client().Discovery().ServerVersion(); err != nil {
		return err
	}

	return nil
}

// setsockoptReuseAddrAndPort sets SO_REUSEADDR and SO_REUSEPORT
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
