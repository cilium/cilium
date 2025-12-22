// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"errors"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestIsTransientError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
		{
			name:     "connection refused",
			err:      syscall.ECONNREFUSED,
			expected: true,
		},
		{
			name:     "connection reset",
			err:      syscall.ECONNRESET,
			expected: true,
		},
		{
			name:     "no route to host",
			err:      syscall.EHOSTUNREACH,
			expected: true,
		},
		{
			name:     "network unreachable",
			err:      syscall.ENETUNREACH,
			expected: true,
		},
		{
			name:     "server timeout",
			err:      k8serrors.NewServerTimeout(schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "gatewayclasses"}, "get", 5),
			expected: true,
		},
		{
			name:     "service unavailable",
			err:      k8serrors.NewServiceUnavailable("API server is shutting down"),
			expected: true,
		},
		{
			name:     "too many requests",
			err:      k8serrors.NewTooManyRequests("rate limited", 5),
			expected: true,
		},
		{
			name:     "timeout",
			err:      k8serrors.NewTimeoutError("request timed out", 30),
			expected: true,
		},
		{
			name:     "not found - permanent error",
			err:      k8serrors.NewNotFound(schema.GroupResource{Group: "gateway.networking.k8s.io", Resource: "gatewayclasses"}, "cilium"),
			expected: false,
		},
		{
			name:     "generic error - not transient",
			err:      errors.New("some random error"),
			expected: false,
		},
		{
			name:     "wrapped connection refused",
			err:      errors.New("dial tcp: connect: " + syscall.ECONNREFUSED.Error()),
			expected: false, // string matching won't work, only errors.As
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isTransientError(tt.err)
			assert.Equal(t, tt.expected, result, "isTransientError(%v) should return %v", tt.err, tt.expected)
		})
	}
}
