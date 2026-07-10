// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dial

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
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

// NewStaticContextDialerWithFallback returns a dialer that maps the specified hostname
// to the provided list of IP addresses if the hostname matches or use the fallback otherwise.
// If the hostname matched, the dialer will attempt to connect to each IP address
// with a partial deadline distribution similar to net.Dial.
func NewStaticContextDialerWithFallback(
	log *slog.Logger, hostAliases map[string][]netip.Addr, fallback dialContextFn,
) dialContextFn {
	return newStaticContextDialerWithFallback(log, func(ctx context.Context, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}, hostAliases, fallback)
}

// newStaticContextDialerWithFallback is mostly adapted from Go's net/dial.go
// dialSerial adapted for our static use case
func newStaticContextDialerWithFallback(
	log *slog.Logger, dialContext dialContextFn, hostAliases map[string][]netip.Addr, fallback dialContextFn,
) dialContextFn {
	var lastConnectedIP *netip.Addr
	return func(ctx context.Context, hostport string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(hostport)
		if err != nil {
			// Return the same error that DialContext would return in this case.
			return nil, &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: err}
		}

		ips, ok := hostAliases[host]
		if !ok {
			return fallback(ctx, hostport)
		}

		// Shuffle IPs to distribute load, but place the last successfully connected IP first
		shuffledIPs := shuffleIPsWithLastConnectedIPAffinity(ips, lastConnectedIP)

		// From this point on, this is mostly the same logic from Go's net/dial.go dialSerial
		var firstErr error

		for i, ip := range shuffledIPs {
			select {
			case <-ctx.Done():
				return nil, &net.OpError{Op: "dial", Net: "tcp", Source: nil, Addr: nil, Err: ctx.Err()}
			default:
			}

			dialCtx := ctx
			if deadline, hasDeadline := ctx.Deadline(); hasDeadline {
				partialDeadline, err := partialDeadline(time.Now(), deadline, len(shuffledIPs)-i)
				if err != nil {
					// Ran out of time.
					if firstErr == nil {
						firstErr = err
					}
					break
				}
				if partialDeadline.Before(deadline) {
					var cancel context.CancelFunc
					dialCtx, cancel = context.WithDeadline(ctx, partialDeadline)
					defer cancel()
				}
			}

			addr := net.JoinHostPort(ip.String(), port)
			log.Debug(
				"Attempting connection via static dialer",
				logfields.Address, host,
				logfields.Target, addr,
			)
			conn, err := dialContext(dialCtx, addr)
			if err == nil {
				lastConnectedIP = &ip
				return conn, nil
			}
			if firstErr == nil {
				firstErr = err
			}
			log.Debug(
				"Connection attempt via static dialer failed, trying next IP",
				logfields.Target, addr,
				logfields.Error, err,
			)
		}
		return nil, firstErr
	}
}

// partialDeadline returns the deadline to use for a single address,
// when multiple addresses are pending.
//
// Copied from Go's net/dial.go to implement a timeout distribution behavior
func partialDeadline(now, deadline time.Time, addrsRemaining int) (time.Time, error) {
	if deadline.IsZero() {
		return deadline, nil
	}
	timeRemaining := deadline.Sub(now)
	if timeRemaining <= 0 {
		return time.Time{}, errors.New("i/o timeout")
	}
	// Tentatively allocate equal time to each remaining address.
	timeout := timeRemaining / time.Duration(addrsRemaining)
	// If the time per address is too short, steal from the end of the list.
	const saneMinimum = 2 * time.Second
	if timeout < saneMinimum {
		// Note that this part was modified to use "min" to make our
		// golangci-lint modernize linter happy
		timeout = min(timeRemaining, saneMinimum)
	}
	return now.Add(timeout), nil
}

// shuffleIPsWithLastConnectedIPAffinity returns a shuffled copy of the IPs with the affinity IP
// (if valid and present) placed first
func shuffleIPsWithLastConnectedIPAffinity(
	ips []netip.Addr, lastConnectedIP *netip.Addr,
) []netip.Addr {
	retIPs := slices.Clone(ips)

	lastIPIndex := -1
	toShuffle := retIPs
	if lastConnectedIP != nil {
		lastIPIndex = slices.Index(retIPs, *lastConnectedIP)
	}

	if lastIPIndex >= 0 {
		// Swap the last successfully connected IP first and mark the rest of the slice for shuffling
		retIPs[0], retIPs[lastIPIndex] = retIPs[lastIPIndex], retIPs[0]
		toShuffle = retIPs[1:]
	}

	rand.Shuffle(len(toShuffle), func(i, j int) { toShuffle[i], toShuffle[j] = toShuffle[j], toShuffle[i] })

	return retIPs
}
