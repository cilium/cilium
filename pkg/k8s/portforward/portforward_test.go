// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package portforward

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/apimachinery/pkg/util/httpstream"
)

func TestShouldFallbackToWebSocket(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "nil error",
			err:  nil,
			want: false,
		},
		{
			name: "plain-string SPDY upgrade rejection (e.g. a proxy that doesn't return the typed error)",
			err:  errors.New("unable to upgrade connection: SPDY protocol is not supported"),
			want: true,
		},
		{
			name: "upgrade rejection in different case",
			err:  errors.New("Unable to Upgrade Connection: SPDY protocol is not supported"),
			want: true,
		},
		{
			name: "wrapped plain-string SPDY upgrade rejection",
			err:  fmt.Errorf("exec failed: %w", errors.New("unable to upgrade connection: SPDY protocol is not supported")),
			want: true,
		},
		{
			name: "typed UpgradeFailureError",
			err:  &httpstream.UpgradeFailureError{Cause: errors.New("boom")},
			want: true,
		},
		{
			name: "error mentions spdy but is not an upgrade failure",
			err:  errors.New("received unexpected spdy frame after stream established"),
			want: false,
		},
		{
			name: "unrelated error",
			err:  errors.New("connection refused"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ShouldFallbackToWebSocket(tt.err))
		})
	}
}
