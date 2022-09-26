// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

//go:build !privileged_tests

package seven

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTraceIDFromHTTPHeader(t *testing.T) {
	tests := []struct {
		name   string
		header http.Header
		want   string
	}{
		{
			name: "no trace",
			want: "",
		}, {
			name: "example traceparent",
			header: http.Header{
				"Traceparent": []string{"00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"},
			},
			want: "4bf92f3577b34da6a3ce929d0e0e4736",
		}, {
			name: "invalid trace",
			header: http.Header{
				"Traceparent": []string{"not-an-actual-traceparent"},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := traceIDFromHTTPHeader(tt.header)
			assert.Equal(t, tt.want, got)
		})
	}
}
