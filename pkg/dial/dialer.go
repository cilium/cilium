// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dial

import (
	"context"
	"log/slog"
	"net"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

type Resolver interface {
	// Resolve translates the provided hostname into the corresponding IP address, or
	// possibly another alias DNS name. An error is returned if no mapping is found.
	Resolve(ctx context.Context, host string) (string, error)
}

type dialContextFn func(context.Context, string) (net.Conn, error)

// NewContextDialer returns a custom dialer associated with a set of resolvers,
// that map the target hostname into the corresponding IP address (or a possible
// alias DNS name). The dialer eventually calls (&net.Dialer{}).DialContext with
// the first successfully translated address, or the original one otherwise.
func NewContextDialer(log *slog.Logger, resolvers ...Resolver) dialContextFn {
	return newContextDialer(log, func(ctx context.Context, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}, resolvers...)
}

func newContextDialer(log *slog.Logger, dialContext dialContextFn, resolvers ...Resolver) dialContextFn {
	return func(ctx context.Context, hostport string) (conn net.Conn, e error) {
		host, port, err := net.SplitHostPort(hostport)
		if err != nil {
			// Return the same error that DialContext would return in this case.
			return nil, &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: err}
		}

		for _, resolver := range resolvers {
			if resolved, err := resolver.Resolve(ctx, host); err == nil {
				log.Debug(
					"Resolved hostname via custom dialer",
					logfields.Address, host,
					logfields.Port, port,
					logfields.Target, resolved,
				)

				hostport = net.JoinHostPort(resolved, port)
				break
			}
		}

		return dialContext(ctx, hostport)
	}
}
