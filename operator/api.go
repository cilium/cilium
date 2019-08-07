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
	"net/http"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
)

// startServer starts an api server listening on the given address.
func startServer(addr string, shutdownSignal <-chan struct{}, allSystemsGo <-chan struct{}) {
	log.Infof("Starting apiserver on address %s", addr)

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		select {
		// only start serving the real health check once all systems all up and running
		case <-allSystemsGo:
			healthHandler(w, r)
		default:
			healthHandlerOK(w, r)
		}
	})

	srv := &http.Server{Addr: addr}

	go func() {
		<-shutdownSignal
		if err := srv.Shutdown(context.Background()); err != nil {
			log.WithError(err).Error("apiserver shutdown")
		}
	}()

	log.Fatalf("Unable to start status api: %s", srv.ListenAndServe())
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
		if client := kvstore.Client(); client == nil {
			return fmt.Errorf("kvstore client not configured")
		} else if _, err := client.Status(); err != nil {
			return err
		}
	}

	if _, err := k8s.Client().Discovery().ServerVersion(); err != nil {
		return err
	}

	return nil
}
