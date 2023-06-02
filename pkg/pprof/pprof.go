// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package pprof enables use of pprof in Cilium
package pprof

import (
	"errors"
	"net"
	"net/http"
	_ "net/http/pprof"
	"strconv"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "pprof")

// Enable runs an HTTP server to serve the pprof API
//
// Deprecated: use pprof.Cell() instead.
func Enable(host string, port int) {
	var apiAddress = net.JoinHostPort(host, strconv.Itoa(port))
	go func() {
		if err := http.ListenAndServe(apiAddress, nil); !errors.Is(err, http.ErrServerClosed) {
			log.WithError(err).Warn("Unable to serve pprof API")
		}
	}()
}
