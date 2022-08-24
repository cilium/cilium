// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

//go:build !privileged_tests

package http

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_httpPlugin_HelpText(t *testing.T) {
	plugin := &httpPlugin{}
	expected := `http - HTTP metrics
Metrics related to the HTTP protocol

Metrics:
  http_requests_total           - Count of HTTP requests by methods.
  http_responses_total          - Count of HTTP responses by methods and status codes.
  http_request_duration_seconds - Median, 90th and 99th percentile of request duration.

Options:
 sourceContext          ::= identifier , { "|", identifier }
 destinationContext     ::= identifier , { "|", identifier }
 labels                 ::= label , { ",", label }
 identifier             ::= identity | namespace | pod | pod-short | dns | ip | reserved-identity
 label                  ::= source_pod | source_namespace | source_workload | source_app | destination_pod | destination_namespace | destination_workload | destination_app | traffic_direction
`
	assert.Equal(t, expected, plugin.HelpText())
}
