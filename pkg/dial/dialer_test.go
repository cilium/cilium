// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dial

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockResolver struct{ before, after string }

func (mr mockResolver) Resolve(_ context.Context, host string) (string, error) {
	if host != mr.before {
		return "", errors.New("unknown translation")
	}

	return mr.after, nil
}

func TestNewContextDialer(t *testing.T) {
	tests := []struct {
		hostport  string
		expected  string
		assertErr assert.ErrorAssertionFunc
	}{
		{
			hostport:  "foo.bar",
			assertErr: assert.Error,
		},
		{
			hostport:  "[fd00::9999]:8080",
			expected:  "[fd00::9999]:8080",
			assertErr: assert.NoError,
		},
		{
			hostport:  "foo.bar:9090",
			expected:  "foo.bar:9090",
			assertErr: assert.NoError,
		},
		{
			hostport:  "resolve.foo:8888",
			expected:  "1.2.3.4:8888",
			assertErr: assert.NoError,
		},
		{
			hostport:  "resolve.bar:9999",
			expected:  "[fd00::8888]:9999",
			assertErr: assert.NoError,
		},
		{
			hostport:  "resolve.baz:9898",
			expected:  "qux.fred:9898",
			assertErr: assert.NoError,
		},
	}

	ctx := context.Background()
	var expected string

	upstream := func(uctx context.Context, address string) (net.Conn, error) {
		assert.Equal(t, ctx, uctx, "context not propagated correctly")
		assert.Equal(t, expected, address, "address not translated correctly")
		return nil, nil
	}

	dialer := newContextDialer(
		slog.Default(),
		upstream,
		mockResolver{"resolve.foo", "1.2.3.4"},
		mockResolver{"resolve.bar", "fd00::8888"},
		mockResolver{"resolve.baz", "qux.fred"},
	)

	for _, tt := range tests {
		expected = tt.expected
		_, err := dialer(ctx, tt.hostport)
		tt.assertErr(t, err, "Got incorrect error for address %q", tt.hostport)
	}
}
