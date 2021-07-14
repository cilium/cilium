// SPDX-License-Identifier: Apache-2.0
// Copyright 2017 Authors of Cilium

// Package pprof enables use of pprof in Cilium
package pprof

import (
	"net"
	"net/http"
	_ "net/http/pprof"
	"strconv"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "pprof")

// Enable runs an HTTP server to serve the pprof API
func Enable(port int) {
	var apiAddress = net.JoinHostPort("localhost", strconv.Itoa(port))
	go func() {
		if err := http.ListenAndServe(apiAddress, nil); err != nil {
			log.WithError(err).Warn("Unable to serve pprof API")
		}
	}()
}
