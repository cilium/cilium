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
	// Resolve maps the provided host and port, according to the implemented strategy
	// (e.g., DNS resolution, service load-balancing, ...). The original host and port
	// must be returned in case no mapping can be found.
	Resolve(ctx context.Context, host, port string) (string, string)
}

type dialContextFn func(context.Context, string) (net.Conn, error)

// NewContextDialer returns a custom dialer associated with a set of resolvers,
// that map the provided address/port pair according to the implemented strategy.
// The dialer eventually calls (&net.Dialer{}).DialContext on the address/port
// pair returned by the sequential execution of all provided resolvers.
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

		oldHost, oldPort := host, port
		for _, resolver := range resolvers {
			host, port = resolver.Resolve(ctx, host, port)
		}

		if oldHost != host || oldPort != port {
			hostport = net.JoinHostPort(host, port)
			log.Debug(
				"Resolved hostport via custom dialer",
				logfields.Address, oldHost,
				logfields.Port, oldPort,
				logfields.Target, hostport,
			)
		}

		return dialContext(ctx, hostport)
	}
}
