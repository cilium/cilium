package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/kvstore"
)

// StartServer starts an api server listening on the given address.
func StartServer(addr string, shutdownSignal <-chan struct{}) {
	log.Infof("Starting apiserver on address %s", addr)

	http.HandleFunc("/healthz", healthHandler)

	srv := &http.Server{Addr: addr}

	go func() {
		<-shutdownSignal
		if err := srv.Shutdown(context.Background()); err != nil {
			log.WithError(err).Error("apiserver shutdown")
		}
	}()

	if err := srv.ListenAndServe(); err != nil {
		log.WithError(err).Error("apiserver listen")
	}
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	statusCode := http.StatusOK
	reply := "ok"

	if err := checkStatus(); err != nil {
		statusCode = http.StatusInternalServerError
		reply = err.Error()
	}

	w.WriteHeader(statusCode)
	if _, err := w.Write([]byte(reply)); err != nil {
		log.WithError(err).Error("Failed to write liveness-probe response")
	}
}

// checkStatus checks the connection status to the kvstore and
// k8s apiserver and returns an error if any of them is unhealthy
func checkStatus() error {

	if client := kvstore.Client(); client == nil {
		return fmt.Errorf("kvstore client not configured")
	} else if _, err := client.Status(); err != nil {
		return err
	} else if _, err := k8s.Client().Discovery().ServerVersion(); err != nil {
		return err
	}

	return nil
}
