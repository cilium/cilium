// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"net/http"

	"github.com/cilium/cilium/pkg/hive/cell"
)

var helloHandlerCell = cell.Module(
	"hello-handler",
	"Implements the hello HTTP handler",

	cell.Provide(newHelloHandler),
)

func newHelloHandler(ExampleMetrics exampleMetrics) HTTPHandlerOut {
	return HTTPHandlerOut{
		HTTPHandler: HTTPHandler{
			Path: "/hello",
			Handler: func(w http.ResponseWriter, req *http.Request) {
				ExampleMetrics.ExampleCounter.Inc()
				w.Write([]byte("Hello\n"))
			},
		},
	}
}
