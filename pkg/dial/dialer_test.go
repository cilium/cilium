// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dial

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
)

type mockResolver struct{ beforeHost, afterHost, afterPort string }

func (mr mockResolver) Resolve(_ context.Context, host, port string) (string, string) {
	if host != mr.beforeHost {
		return host, port
	}

	return mr.afterHost, cmp.Or(mr.afterPort, port)
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
			hostport:  "1.2.3.4:8888",
			expected:  "5.6.7.8:9090",
			assertErr: assert.NoError,
		},
		{
			hostport:  "resolve.foo:8888",
			expected:  "5.6.7.8:9090",
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
		mockResolver{"resolve.foo", "1.2.3.4", ""},
		mockResolver{"resolve.bar", "fd00::8888", ""},
		mockResolver{"1.2.3.4", "5.6.7.8", "9090"},
		mockResolver{"resolve.baz", "qux.fred", ""},
	)

	for _, tt := range tests {
		expected = tt.expected
		_, err := dialer(ctx, tt.hostport)
		tt.assertErr(t, err, "Got incorrect error for address %q", tt.hostport)
	}
}

func TestNewStaticContextDialerWithFallback(t *testing.T) {
	t.Run("succeeds on first IP", func(t *testing.T) {
		var attempts []string

		upstream := func(_ context.Context, address string) (net.Conn, error) {
			attempts = append(attempts, address)
			return nil, nil // succeed on first attempt
		}

		fallback := func(_ context.Context, address string) (net.Conn, error) {
			t.Fatal("fallback should not be called")
			return nil, nil
		}

		dialer := newStaticContextDialerWithFallback(
			slog.Default(),
			upstream,
			map[string][]netip.Addr{
				"cluster1.mesh.cilium.io": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
			},
			fallback,
		)

		_, err := dialer(t.Context(), "cluster1.mesh.cilium.io:2379")
		assert.NoError(t, err)
		assert.Len(t, attempts, 1)
	})

	t.Run("succeeds on last IP", func(t *testing.T) {
		var attempts []string

		upstream := func(_ context.Context, address string) (net.Conn, error) {
			attempts = append(attempts, address)
			if len(attempts) < 3 {
				return nil, errors.New("connection refused")
			}
			return nil, nil // succeed on third attempt
		}

		fallback := func(_ context.Context, address string) (net.Conn, error) {
			t.Fatal("fallback should not be called")
			return nil, nil
		}

		dialer := newStaticContextDialerWithFallback(
			slog.Default(),
			upstream,
			map[string][]netip.Addr{
				"cluster1.mesh.cilium.io": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
			},
			fallback,
		)

		_, err := dialer(t.Context(), "cluster1.mesh.cilium.io:2379")
		assert.NoError(t, err)
		assert.ElementsMatch(t, []string{"10.0.0.1:2379", "10.0.0.2:2379", "10.0.0.3:2379"}, attempts)
	})

	t.Run("all IPs fail returns first error", func(t *testing.T) {
		var attempts []string

		upstream := func(_ context.Context, address string) (net.Conn, error) {
			attempts = append(attempts, address)
			return nil, errors.New("connection refused to " + address)
		}

		fallback := func(_ context.Context, address string) (net.Conn, error) {
			t.Fatal("fallback should not be called")
			return nil, nil
		}

		dialer := newStaticContextDialerWithFallback(
			slog.Default(),
			upstream,
			map[string][]netip.Addr{
				"cluster1.mesh.cilium.io": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
				},
			},
			fallback,
		)

		_, err := dialer(t.Context(), "cluster1.mesh.cilium.io:2379")
		assert.Len(t, attempts, 2)
		assert.ElementsMatch(t, []string{"10.0.0.1:2379", "10.0.0.2:2379"}, attempts)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "connection refused to "+attempts[0])
	})

	t.Run("uses fallback if hostname doesn't match", func(t *testing.T) {
		var dialedAddress string

		upstream := func(_ context.Context, address string) (net.Conn, error) {
			t.Fatal("upstream should not be called")
			return nil, nil
		}

		fallback := func(_ context.Context, address string) (net.Conn, error) {
			dialedAddress = address
			return nil, nil
		}

		dialer := newStaticContextDialerWithFallback(
			slog.Default(),
			upstream,
			map[string][]netip.Addr{
				"cluster1.mesh.cilium.io": {netip.MustParseAddr("10.0.0.1")},
			},
			fallback,
		)

		_, err := dialer(t.Context(), "some-other-host.local:8080")
		assert.NoError(t, err)
		assert.Equal(t, "some-other-host.local:8080", dialedAddress)
	})

	t.Run("context canceled returns immediately", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel() // cancel immediately

		upstream := func(_ context.Context, address string) (net.Conn, error) {
			t.Fatal("fallback should not be called")
			return nil, nil
		}

		fallback := func(_ context.Context, address string) (net.Conn, error) {
			t.Fatal("fallback should not be called")
			return nil, nil
		}

		dialer := newStaticContextDialerWithFallback(
			slog.Default(),
			upstream,
			map[string][]netip.Addr{
				"cluster1.mesh.cilium.io": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
				},
			},
			fallback,
		)

		_, err := dialer(ctx, "cluster1.mesh.cilium.io:2379")
		assert.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("context canceled mid-iteration", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		var attempts []string

		upstream := func(_ context.Context, address string) (net.Conn, error) {
			attempts = append(attempts, address)
			cancel() // cancel after first attempt
			return nil, errors.New("connection refused to " + address)
		}

		fallback := func(_ context.Context, address string) (net.Conn, error) {
			t.Fatal("fallback should not be called")
			return nil, nil
		}

		dialer := newStaticContextDialerWithFallback(
			slog.Default(),
			upstream,
			map[string][]netip.Addr{
				"cluster1.mesh.cilium.io": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
			},
			fallback,
		)

		_, err := dialer(ctx, "cluster1.mesh.cilium.io:2379")
		assert.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Len(t, attempts, 1, "should have stopped after first attempt")
	})

	t.Run("timeout is distributed across IPs and remaining time", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 16*time.Second)
			defer cancel()

			var timeouts []time.Duration

			upstream := func(ctx context.Context, address string) (net.Conn, error) {
				deadline, ok := ctx.Deadline()
				assert.True(t, ok, "expected deadline to be set")
				timeouts = append(timeouts, time.Until(deadline))

				switch len(timeouts) {
				case 1:
					// simulate timeout
					<-ctx.Done()
					return nil, ctx.Err()
				case 2:
					// simulate immediate failure
					return nil, errors.New("connection refused")
				case 3:
					// simulate failure after some delay
					time.Sleep(2 * time.Second)
					return nil, errors.New("connection refused")
				}

				// Succeed on fourth attempt
				return nil, nil
			}

			fallback := func(_ context.Context, address string) (net.Conn, error) {
				t.Fatal("fallback should not be called")
				return nil, nil
			}

			dialer := newStaticContextDialerWithFallback(
				slog.Default(),
				upstream,
				map[string][]netip.Addr{
					"cluster1.mesh.cilium.io": {
						netip.MustParseAddr("10.0.0.1"),
						netip.MustParseAddr("10.0.0.2"),
						netip.MustParseAddr("10.0.0.3"),
						netip.MustParseAddr("10.0.0.4"),
					},
				},
				fallback,
			)

			_, err := dialer(ctx, "cluster1.mesh.cilium.io:2379")
			assert.NoError(t, err)
			assert.Len(t, timeouts, 4)

			assert.Equal(t, 4*time.Second, timeouts[0], "first IP should get 16s/4 = 4s")
			assert.Equal(t, 4*time.Second, timeouts[1], "second IP should get 12s/3 = 4s")
			assert.Equal(t, 6*time.Second, timeouts[2], "third IP should get 12s/2 = 6s")
			assert.Equal(t, 10*time.Second, timeouts[3], "fourth IP should get 10s/1 = 10s")
		})
	})

	t.Run("try last connected IP first on reconnection", func(t *testing.T) {
		var attempts []string

		upstream := func(_ context.Context, address string) (net.Conn, error) {
			attempts = append(attempts, address)
			// First connection: fail until we hit 10.0.0.2, which succeeds
			// Second connection: should try 10.0.0.2 first due to affinity
			if address == "10.0.0.2:2379" {
				return nil, nil // succeed
			}
			return nil, errors.New("connection refused")
		}

		fallback := func(_ context.Context, address string) (net.Conn, error) {
			t.Fatal("fallback should not be called")
			return nil, nil
		}

		dialer := newStaticContextDialerWithFallback(
			slog.Default(),
			upstream,
			map[string][]netip.Addr{
				"cluster1.mesh.cilium.io": {
					netip.MustParseAddr("10.0.0.1"),
					netip.MustParseAddr("10.0.0.2"),
					netip.MustParseAddr("10.0.0.3"),
				},
			},
			fallback,
		)

		// First connection
		_, err := dialer(t.Context(), "cluster1.mesh.cilium.io:2379")
		assert.NoError(t, err)

		firstConnAttempts := len(attempts)

		// Second connection
		_, err = dialer(t.Context(), "cluster1.mesh.cilium.io:2379")
		assert.NoError(t, err)

		// The second connection should have tried 10.0.0.2 first
		assert.Equal(t, "10.0.0.2:2379", attempts[firstConnAttempts], "second connection try last connected IP first")
	})
}
