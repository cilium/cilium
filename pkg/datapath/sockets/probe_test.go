// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sockets

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	"github.com/cilium/cilium/pkg/testutils"

	"github.com/cilium/hive/hivetest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TestPrivilegedProbetInetDiagDestroyEnabled is the end-to-end smoke test: with
// real privileges it exercises the full netlink inet_diag list+destroy path and
// asserts the kernel supports socket termination for both TCP and UDP. The
// unprivileged tests below stub netlink to cover the surrounding logic.
func TestPrivilegedProbetInetDiagDestroyEnabled(t *testing.T) {
	testutils.PrivilegedTest(t)
	p := newSocketInetProbe()
	assert.NoError(t, p.InetDiagDestroyTCPEnabled(hivetest.Logger(t)))
	assert.NoError(t, p.InetDiagDestroyUDPEnabled(hivetest.Logger(t)))
}

// fakeNetlink stubs the privileged netlink inet_diag operations (iterate /
// destroySocket) so the probing logic can be tested without CAP_NET_ADMIN. It
// records destroyed sockets and can inject list/destroy errors.
type fakeNetlink struct {
	// sockets returned by iterate for a given protocol.
	sockets map[uint8][]netlink.Socket
	// iterErr, if set, is passed to the callback (simulating a per-message error).
	iterErr error
	// destroyErr, if set, is returned from destroySocket.
	destroyErr error

	destroyed []netlink.Socket
}

func (f *fakeNetlink) iterate(proto uint8, family uint8, stateFilter uint32, fn func(*netlink.Socket, error) error) error {
	if f.iterErr != nil {
		// Mirror the openSubscribeHandle failure path, where Iterate returns
		// the error directly rather than via the callback.
		//
		// TODO: the real iterateNetlinkSockets has a second error path we don't
		// model here: per-message errors (short reads, NLMSG_ERROR, wrong sender
		// PID) are delivered to the callback as fn(nil, err) while iteration
		// continues, not returned directly. The probe callback guards this with
		// its `if err != nil` check, but that path is currently only covered
		// indirectly. Extend fakeNetlink to optionally inject a per-message
		// error via the callback so we exercise that branch explicitly.
		return f.iterErr
	}
	for i := range f.sockets[proto] {
		s := f.sockets[proto][i]
		if err := fn(&s, nil); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeNetlink) destroySocket(logger *slog.Logger, sock netlink.Socket, proto netlink.Proto, stateFilter uint32) error {
	if f.destroyErr != nil {
		return f.destroyErr
	}
	f.destroyed = append(f.destroyed, sock)
	return nil
}

// captureFns wraps the real socket creators but records the ports handed out so
// the fake netlink layer can return a matching socket.
func captureFns(t *testing.T, fnl *fakeNetlink) probeSocketFns {
	lo := net.IP{127, 0, 0, 1}
	return probeSocketFns{
		createProbeTCPSocket: func(ctx context.Context) (*net.TCPListener, net.Conn, uint16, error) {
			lis, conn, port, err := createProbeTCPSocket(ctx)
			if err != nil {
				return nil, nil, 0, err
			}
			fnl.sockets[unix.IPPROTO_TCP] = append(fnl.sockets[unix.IPPROTO_TCP], netlink.Socket{
				ID: netlink.SocketID{SourcePort: port, Source: lo},
			})
			return lis, conn, port, nil
		},
		createProbeUDPSocket: func() (closer, uint16, error) {
			c, port, err := createProbeUDPSocket()
			if err != nil {
				return c, 0, err
			}
			fnl.sockets[unix.IPPROTO_UDP] = append(fnl.sockets[unix.IPPROTO_UDP], netlink.Socket{
				ID: netlink.SocketID{SourcePort: port, Source: lo},
			})
			return c, port, nil
		},
		iterate:       fnl.iterate,
		destroySocket: fnl.destroySocket,
	}
}

func newFakeNetlink() *fakeNetlink {
	return &fakeNetlink{sockets: map[uint8][]netlink.Socket{}}
}

// TestProbeForSockDestroy_Success covers the happy path: the single probe socket
// that is created is found during iteration and successfully destroyed, and no
// error is returned.
func TestProbeForSockDestroy_Success(t *testing.T) {
	// probe runs the probe for one protocol (udp=false means TCP) and asserts
	// the created socket was found and destroyed.
	probe := func(t *testing.T, udp bool) {
		fnl := newFakeNetlink()
		fns := captureFns(t, fnl)
		p := &SocketInetProbe{probeSocketFns: fns}

		require.NoError(t, p.probeForSockDestroy(t.Context(), hivetest.Logger(t), udp))
		require.Len(t, fnl.destroyed, 1)
	}

	t.Run("tcp", func(t *testing.T) { probe(t, false) })
	t.Run("udp", func(t *testing.T) { probe(t, true) })
}

// TestProbeForSockDestroy_DestroyUnsupported verifies that an ENOTSUP from the
// destroy operation is surfaced as ErrNotSupported, hinting that the kernel is
// missing CONFIG_INET_DIAG_DESTROY.
func TestProbeForSockDestroy_DestroyUnsupported(t *testing.T) {
	fnl := newFakeNetlink()
	fnl.destroyErr = unix.ENOTSUP
	fns := captureFns(t, fnl)
	p := &SocketInetProbe{probeSocketFns: fns}

	err := p.probeForSockDestroy(t.Context(), hivetest.Logger(t), false)
	require.Error(t, err)
	require.ErrorIs(t, err, probes.ErrNotSupported)
}

// TestProbeForSockDestroy_NoSocketsListed verifies that when iteration lists no
// sockets at all (not even our own probe socket) the probe concludes the
// *_DIAG listing config is missing and returns ErrNotSupported.
func TestProbeForSockDestroy_NoSocketsListed(t *testing.T) {
	fnl := newFakeNetlink()
	fns := captureFns(t, fnl)
	// Drop the socket the creator registered so iterate yields nothing.
	fns.iterate = func(proto uint8, family uint8, stateFilter uint32, fn func(*netlink.Socket, error) error) error {
		return nil
	}
	p := &SocketInetProbe{probeSocketFns: fns}

	err := p.probeForSockDestroy(t.Context(), hivetest.Logger(t), false)
	require.Error(t, err)
	require.ErrorIs(t, err, probes.ErrNotSupported)
}

// TestProbeForSockDestroy_OtherSocketsButNotOurs checks the "unexpected" case
// where we manage to list sockets but do not find a match.
func TestProbeForSockDestroy_OtherSocketsButNotOurs(t *testing.T) {
	fnl := newFakeNetlink()
	fns := captureFns(t, fnl)
	fns.iterate = func(proto uint8, family uint8, stateFilter uint32, fn func(*netlink.Socket, error) error) error {
		// A socket that doesn't match (different port, non-loopback source).
		return fn(&netlink.Socket{
			ID: netlink.SocketID{SourcePort: 1, Source: net.IP{10, 0, 0, 1}},
		}, nil)
	}
	p := &SocketInetProbe{probeSocketFns: fns}

	err := p.probeForSockDestroy(t.Context(), hivetest.Logger(t), false)
	require.Error(t, err)
	require.NotErrorIs(t, err, probes.ErrNotSupported)
	require.Empty(t, fnl.destroyed)
}

// TestProbeForSockDestroy_IterateError verifies that a netlink-level error
// returned directly from iterate (e.g. the socket subscribe handle fails) is
// joined into the probe's returned error.
func TestProbeForSockDestroy_IterateError(t *testing.T) {
	fnl := newFakeNetlink()
	fnl.iterErr = errors.New("boom")
	fns := captureFns(t, fnl)
	p := &SocketInetProbe{probeSocketFns: fns}

	err := p.probeForSockDestroy(t.Context(), hivetest.Logger(t), true)
	require.Error(t, err)
	require.ErrorContains(t, err, "boom")
}

// TestProbeForSockDestroy_ContextCancelledDuringIterate verifies that a context
// cancel prior to the first destroy is respected.
func TestProbeForSockDestroy_ContextCancelledDuringIterate(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())

	fnl := newFakeNetlink()
	fns := captureFns(t, fnl)
	fns.iterate = func(proto uint8, family uint8, stateFilter uint32, fn func(*netlink.Socket, error) error) error {
		// Cancel just before delivering a matching socket; the callback's
		// ctx.Err() check must fire before it attempts a destroy.
		cancel()
		return fn(&netlink.Socket{
			ID: netlink.SocketID{SourcePort: 1234, Source: net.IP{127, 0, 0, 1}},
		}, nil)
	}
	p := &SocketInetProbe{probeSocketFns: fns}

	err := p.probeForSockDestroy(ctx, hivetest.Logger(t), false)
	require.ErrorIs(t, err, context.Canceled)
	require.Empty(t, fnl.destroyed)
}

// TestInetDiagDestroyEnabled_MemoizesResult verifies that the exported wrappers
// run the underlying probe only once for a definitive (success) result and
// return the memoized value on subsequent calls, per protocol.
func TestInetDiagDestroyEnabled_MemoizesResult(t *testing.T) {
	fnl := newFakeNetlink()
	fns := captureFns(t, fnl)

	tcpCreates := 0
	realTCP := fns.createProbeTCPSocket
	fns.createProbeTCPSocket = func(ctx context.Context) (*net.TCPListener, net.Conn, uint16, error) {
		tcpCreates++
		return realTCP(ctx)
	}
	udpCreates := 0
	realUDP := fns.createProbeUDPSocket
	fns.createProbeUDPSocket = func() (closer, uint16, error) {
		udpCreates++
		return realUDP()
	}
	p := &SocketInetProbe{probeSocketFns: fns}

	logger := hivetest.Logger(t)
	for range 3 {
		require.NoError(t, p.InetDiagDestroyTCPEnabled(logger))
		require.NoError(t, p.InetDiagDestroyUDPEnabled(logger))
	}

	// Despite three calls each, the probe (and thus socket creation) runs once
	// per protocol.
	require.Equal(t, 1, tcpCreates, "TCP probe should run exactly once")
	require.Equal(t, 1, udpCreates, "UDP probe should run exactly once")
}

// TestInetDiagDestroyEnabled_TCPAndUDPStoredSeparately is a regression test for
// the original memoization bug where a shared result pinned both protocols to
// whichever ran first. Here UDP fails with ErrNotSupported while TCP succeeds;
// each wrapper must report its own independent result, including on repeat calls.
func TestInetDiagDestroyEnabled_TCPAndUDPStoredSeparately(t *testing.T) {
	fnl := newFakeNetlink()
	fns := captureFns(t, fnl)
	// Make only UDP destroys fail; TCP must still report success.
	fns.destroySocket = func(logger *slog.Logger, sock netlink.Socket, proto netlink.Proto, stateFilter uint32) error {
		if proto == netlink.Proto(unix.IPPROTO_UDP) {
			return unix.ENOTSUP
		}
		fnl.destroyed = append(fnl.destroyed, sock)
		return nil
	}
	p := &SocketInetProbe{probeSocketFns: fns}

	logger := hivetest.Logger(t)

	// Drive UDP (failing) first to ensure its result doesn't bleed into TCP.
	udpErr := p.InetDiagDestroyUDPEnabled(logger)
	require.ErrorIs(t, udpErr, probes.ErrNotSupported)

	tcpErr := p.InetDiagDestroyTCPEnabled(logger)
	require.NoError(t, tcpErr, "TCP result must be independent of UDP's failure")

	// And the memoized values stay distinct on repeat calls.
	require.ErrorIs(t, p.InetDiagDestroyUDPEnabled(logger), probes.ErrNotSupported)
	require.NoError(t, p.InetDiagDestroyTCPEnabled(logger))
}

// TestInetDiagDestroyEnabled_UnexpectedError verifies the "retry transient" half
// of the memoization policy: an unexpected error (neither success nor
// ErrNotSupported) is not cached, so a later call re-probes and can succeed -
// after which the success is memoized.
func TestInetDiagDestroyEnabled_UnexpectedError(t *testing.T) {
	fnl := newFakeNetlink()
	fns := captureFns(t, fnl)

	fail := true
	tcpCreates := 0
	realTCP := fns.createProbeTCPSocket
	fns.createProbeTCPSocket = func(ctx context.Context) (*net.TCPListener, net.Conn, uint16, error) {
		tcpCreates++
		if fail {
			return nil, nil, 0, errors.New("transient boom")
		}
		return realTCP(ctx)
	}
	p := &SocketInetProbe{probeSocketFns: fns}

	logger := hivetest.Logger(t)

	// First call fails transiently.
	err := p.InetDiagDestroyTCPEnabled(logger)
	require.ErrorContains(t, err, "transient boom")
	require.NotErrorIs(t, err, probes.ErrNotSupported)

	// Recover, then a subsequent call must re-probe (not return the cached error).
	fail = false
	require.NoError(t, p.InetDiagDestroyTCPEnabled(logger))
	require.Equal(t, 2, tcpCreates, "transient failure should be retried, not memoized")

	// Now that it succeeded, the success is memoized.
	require.NoError(t, p.InetDiagDestroyTCPEnabled(logger))
	require.Equal(t, 2, tcpCreates, "success should be memoized")

	fail = true
	// Probes now should be memoized, so underlying failures shouldn't happen.
	require.NoError(t, p.InetDiagDestroyTCPEnabled(logger))
	require.Equal(t, 2, tcpCreates, "second success should be memoized")
}
