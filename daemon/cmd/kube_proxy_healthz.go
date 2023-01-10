// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
)

// DaemonInterface to help with testing.
type DaemonInterface interface {
	getStatus(bool) models.StatusResponse
}

// ServiceInterface to help with testing.
type ServiceInterface interface {
	GetLastUpdatedTs() time.Time
	GetCurrentTs() time.Time
}

type kubeproxyHealthzHandler struct {
	d   DaemonInterface
	svc ServiceInterface
}

// startKubeProxyHealthzHTTPService registers a handler function for the kube-proxy /healthz
// status HTTP endpoint exposed on addr.
// This endpoint reports the agent health status with the timestamp.
func (d *Daemon) startKubeProxyHealthzHTTPService(addr string) {
	lc := net.ListenConfig{Control: setsockoptReuseAddrAndPort}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	addrField := logrus.Fields{"address": addr}
	if errors.Is(err, unix.EADDRNOTAVAIL) {
		log.WithFields(addrField).Info("KubeProxy healthz server not available")
	} else if err != nil {
		log.WithFields(addrField).WithError(err).Fatal("hint: kube-proxy should not be running nor listening on the same healthz-bind-address.")
	}

	mux := http.NewServeMux()
	mux.Handle("/healthz", kubeproxyHealthzHandler{d: d, svc: d.svc})

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	go func() {
		err := srv.Serve(ln)
		if errors.Is(err, http.ErrServerClosed) {
			log.WithFields(addrField).Info("kube-proxy healthz status API server shutdown")
		} else if err != nil {
			log.WithFields(addrField).WithError(err).Fatal("Unable to start kube-proxy healthz server")
		}
	}()
	log.WithFields(addrField).Info("Started kube-proxy healthz server")
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
	var lastUpdateTs = currentTs
	// We piggy back here on Cilium daemon health. If Cilium is healthy, we can
	// reasonably assume that the node networking is ready.
	sr := h.d.getStatus(true)
	if isUnhealthy(&sr) {
		statusCode = http.StatusServiceUnavailable
		lastUpdateTs = h.svc.GetLastUpdatedTs()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(statusCode)
	fmt.Fprintf(w, `{"lastUpdated": %q,"currentTime": %q}`, lastUpdateTs, currentTs)
}
