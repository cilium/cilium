// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"net/http"

	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/hive/cell"
)

var eventsHandlerCell = cell.Module(
	"events-handler",
	"Implements the events HTTP handler",

	cell.Provide(newEventsHandler),
)

func newEventsHandler(ee ExampleEvents) HTTPHandlerOut {
	return HTTPHandlerOut{
		HTTPHandler: HTTPHandler{
			Path: "/events",
			Handler: func(w http.ResponseWriter, req *http.Request) {
				f := w.(http.Flusher)
				w.WriteHeader(http.StatusOK)

				for ev := range stream.ToChannel[ExampleEvent](req.Context(), ee) {
					fmt.Fprintf(w, "%s\n", ev.Message)
					f.Flush()
				}
			},
		},
	}
}
