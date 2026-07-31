// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/mdlayher/ndp"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	// raInterval is how often an unsolicited Router Advertisement is sent on
	// each unnumbered interface.
	raInterval = 5 * time.Second
	// raReadTimeout bounds each blocking read so the reader goroutine can
	// observe context cancellation promptly.
	raReadTimeout = time.Second
	// raRouterLifetime is the advertised router lifetime. It is non-zero because
	// FRR only treats the sender as a valid unnumbered peer once it has learned
	// its link-local from an RA with a router lifetime (matching radvd's
	// AdvDefaultLifetime default, which is the config proven to work against FRR).
	// A lifetime-0 RA is defined to still set the neighbor IsRouter flag per
	// RFC 4861, but FRR does not accept the unnumbered peer without a non-zero
	// lifetime. The remote side of a BGP-unnumbered link is itself a router that
	// does not install RA-derived default routes, so advertising a lifetime here
	// is safe.
	raRouterLifetime = 30 * time.Minute
)

var (
	allNodesAddr   = netip.MustParseAddr("ff02::1")
	allRoutersAddr = netip.MustParseAddr("ff02::2")
)

// UnnumberedRAReconciler sends IPv6 Router Advertisements on the interfaces used
// by BGP-unnumbered peers.
//
// BGP unnumbered peers (autoDiscovery.mode: Unnumbered) rely on IPv6 ND: the
// remote end (e.g. FRR) only accepts an unnumbered neighbor whose link-local it
// has learned as a *router* from that peer's Router Advertisements. gobgp speaks
// BGP but does not emit RAs, so without this the remote drops our connection
// right after the OPEN ("not configured and not valid for dynamic"). FRR gets
// this for free because zebra sends RAs on unnumbered interfaces; this reconciler
// is the equivalent for Cilium, so no external radvd dependency is required.
//
// It requires CAP_NET_RAW (raw ICMPv6 socket, hop limit 255), which the agent
// already holds.
type UnnumberedRAReconciler struct {
	logger *slog.Logger

	mu sync.Mutex
	// byInstance tracks the unnumbered interfaces desired by each BGP instance,
	// keyed by instance name, so the running senders can match the union across
	// all instances.
	byInstance map[string]map[string]struct{}
	// senders holds the running RA sender per interface.
	senders map[string]*raSender
	// baseCtx is the parent context for RA sender goroutines (agent lifetime).
	baseCtx context.Context
	// newSender constructs the RA sender for an interface. It is a field so
	// tests can substitute a stub that does not open a raw ICMPv6 socket;
	// production wiring points it at newRASender.
	newSender func(ctx context.Context, logger *slog.Logger, ifname string) (*raSender, error)
	// ifIndexOf resolves an interface's current index. It is a field so tests
	// can simulate an interface being re-created; production wiring points it
	// at interfaceIndex.
	ifIndexOf func(ifname string) (int, error)
}

type UnnumberedRAReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

func NewUnnumberedRAReconciler(logger *slog.Logger) UnnumberedRAReconcilerOut {
	return UnnumberedRAReconcilerOut{
		Reconciler: &UnnumberedRAReconciler{
			logger:     logger.With(types.ReconcilerLogField, UnnumberedRAReconcilerName),
			byInstance: make(map[string]map[string]struct{}),
			senders:    make(map[string]*raSender),
			baseCtx:    context.Background(),
			newSender:  newRASender,
			ifIndexOf:  interfaceIndex,
		},
	}
}

// interfaceIndex returns the current kernel index of the named interface.
func interfaceIndex(ifname string) (int, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return 0, err
	}
	return ifi.Index, nil
}

func (r *UnnumberedRAReconciler) Name() string { return UnnumberedRAReconcilerName }

func (r *UnnumberedRAReconciler) Priority() int { return UnnumberedRAReconcilerPriority }

func (r *UnnumberedRAReconciler) Init(_ *instance.BGPInstance) error { return nil }

func (r *UnnumberedRAReconciler) Cleanup(i *instance.BGPInstance) {
	if i == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byInstance, i.Name)
	r.reconcileSendersLocked()
}

func (r *UnnumberedRAReconciler) Reconcile(_ context.Context, p ReconcileParams) error {
	if err := p.ValidateParams(); err != nil {
		return err
	}

	ifaces := make(map[string]struct{})
	for _, peer := range p.DesiredConfig.Peers {
		if peer.AutoDiscovery == nil || peer.AutoDiscovery.Mode != v2.BGPUnnumberedMode {
			continue
		}
		// Read the interface resolved by the DefaultGatewayReconciler rather than
		// the configured one: with mode Unnumbered the interface may be derived
		// from the default route instead of named explicitly. That reconciler has
		// a lower priority, so it has already populated PeerInterface on this
		// config by the time we run.
		ifname := ptr.Deref(peer.PeerInterface, "")
		if ifname == "" {
			continue
		}
		ifaces[ifname] = struct{}{}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(ifaces) == 0 {
		delete(r.byInstance, p.DesiredConfig.Name)
	} else {
		r.byInstance[p.DesiredConfig.Name] = ifaces
	}
	r.reconcileSendersLocked()
	return nil
}

// reconcileSendersLocked starts/stops RA senders so the running set equals the
// union of unnumbered interfaces across all instances. Caller must hold r.mu.
func (r *UnnumberedRAReconciler) reconcileSendersLocked() {
	want := make(map[string]struct{})
	for _, ifs := range r.byInstance {
		for ifname := range ifs {
			want[ifname] = struct{}{}
		}
	}

	for ifname, s := range r.senders {
		if _, ok := want[ifname]; !ok {
			s.stop()
			delete(r.senders, ifname)
			r.logger.Info("Stopped BGP-unnumbered router advertisements", logfields.Interface, ifname)
			continue
		}
		// The interface may have been destroyed and re-created under a running
		// sender (a link re-probe re-creates the netdev with a new index, e.g.
		// when the peer on the other side of the link reboots). The raw socket
		// stays bound to the old index and every send then fails with ENODEV,
		// silently starving the peer of the RAs it needs to accept us as an
		// unnumbered neighbor. Rebind by restarting the sender.
		//
		// A bound index of 0 means the sender is currently between sockets; its
		// own reopen loop owns recovery in that case, so leave it alone.
		bound := s.boundIndex()
		if bound == 0 {
			continue
		}
		current, err := r.ifIndexOf(ifname)
		if err != nil || current == bound {
			continue
		}
		s.stop()
		delete(r.senders, ifname)
		r.logger.Info("Interface was re-created, restarting BGP-unnumbered router advertisements",
			logfields.Interface, ifname, logfields.LinkIndex, current)
	}

	for ifname := range want {
		if _, ok := r.senders[ifname]; ok {
			continue
		}
		s, err := r.newSender(r.baseCtx, r.logger, ifname)
		if err != nil {
			r.logger.Warn("Failed to start BGP-unnumbered router advertisements",
				logfields.Interface, ifname, logfields.Error, err)
			continue
		}
		r.senders[ifname] = s
		r.logger.Info("Started BGP-unnumbered router advertisements", logfields.Interface, ifname)
	}
}

// raSender periodically emits Router Advertisements on a single interface and
// answers Router Solicitations, until stopped.
type raSender struct {
	cancel context.CancelFunc
	done   chan struct{}
	// index is the interface index the current socket is bound to, or 0 while
	// the sender has no open socket.
	index atomic.Int32
}

func (s *raSender) stop() {
	s.cancel()
	<-s.done
}

// boundIndex returns the interface index the sender's socket is bound to, or 0
// if it currently has none.
func (s *raSender) boundIndex() int { return int(s.index.Load()) }

// openRAConn opens the raw ICMPv6 socket for an interface and builds the RA to
// advertise on it. The returned index is the interface index the socket is
// bound to; a socket outlives neither the netdev it was opened on nor its index.
func openRAConn(ifname string) (*ndp.Conn, *ndp.RouterAdvertisement, int, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("interface %q: %w", ifname, err)
	}

	// ndp.Listen sets the required NDP hop limit of 255 on the socket.
	conn, _, err := ndp.Listen(ifi, ndp.LinkLocal)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("ndp listen on %q: %w", ifname, err)
	}
	// Join all-routers so we receive Router Solicitations from the peer.
	if err := conn.JoinGroup(allRoutersAddr); err != nil {
		conn.Close()
		return nil, nil, 0, fmt.Errorf("join all-routers group on %q: %w", ifname, err)
	}

	// A minimal RA: no prefixes, a non-zero router lifetime (see raRouterLifetime),
	// and a source link-layer address option. This is enough for the peer to record
	// our link-local as a router-neighbor in its ND table - the piece unnumbered
	// peering needs - and mirrors radvd's proven "AdvSendAdvert on" defaults.
	ra := &ndp.RouterAdvertisement{
		CurrentHopLimit: 64,
		RouterLifetime:  raRouterLifetime,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{Direction: ndp.Source, Addr: ifi.HardwareAddr},
		},
	}

	return conn, ra, ifi.Index, nil
}

func newRASender(parent context.Context, logger *slog.Logger, ifname string) (*raSender, error) {
	conn, ra, index, err := openRAConn(ifname)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(parent)
	s := &raSender{cancel: cancel, done: make(chan struct{})}
	s.index.Store(int32(index))

	go s.run(ctx, logger, ifname, conn, ra)

	return s, nil
}

// run advertises on conn every raInterval. A send failure means the socket is no
// longer usable - most often because the netdev it is bound to was destroyed and
// re-created with a new index, which makes every write fail with ENODEV - so the
// socket is dropped and re-opened on the next tick. Without this the sender would
// stay silently wedged and the peer would never accept us as an unnumbered
// neighbor.
func (s *raSender) run(ctx context.Context, logger *slog.Logger, ifname string, conn *ndp.Conn, ra *ndp.RouterAdvertisement) {
	defer close(s.done)

	// Each socket gets its own Router Solicitation responder; closing the socket
	// makes that goroutine's read fail so it exits on its own.
	var wg sync.WaitGroup
	startReader := func(c *ndp.Conn, r *ndp.RouterAdvertisement) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			solicitReader(ctx, c, r, logger, ifname)
		}()
	}
	closeConn := func() {
		if conn == nil {
			return
		}
		conn.Close()
		conn, ra = nil, nil
		s.index.Store(0)
	}

	defer func() {
		closeConn()
		wg.Wait()
	}()

	startReader(conn, ra)

	// failures counts consecutive send/reopen failures, so a persistent problem
	// is reported once rather than every raInterval.
	var failures int
	send := func() {
		if conn == nil {
			c, r, index, err := openRAConn(ifname)
			if err != nil {
				failures++
				if failures == 1 {
					logger.Warn("Failed to re-open the BGP-unnumbered router advertisement socket",
						logfields.Interface, ifname, logfields.Error, err)
				} else {
					logger.Debug("Failed to re-open the BGP-unnumbered router advertisement socket",
						logfields.Interface, ifname, logfields.Error, err)
				}
				return
			}
			conn, ra = c, r
			s.index.Store(int32(index))
			startReader(conn, ra)
			// Re-opening is only half the recovery - the next write still has
			// to succeed - so this stays at Debug and the streak is reported
			// once, below, when sending actually resumes.
			logger.Debug("Re-opened the BGP-unnumbered router advertisement socket",
				logfields.Interface, ifname, logfields.LinkIndex, index)
		}

		if err := conn.WriteTo(ra, nil, allNodesAddr); err != nil {
			failures++
			if failures == 1 {
				logger.Warn("Failed to send router advertisement, re-opening the socket",
					logfields.Interface, ifname, logfields.Error, err)
			} else {
				logger.Debug("Failed to send router advertisement, re-opening the socket",
					logfields.Interface, ifname, logfields.Error, err)
			}
			closeConn()
			return
		}

		if failures > 0 {
			logger.Info("Resumed sending BGP-unnumbered router advertisements",
				logfields.Interface, ifname, logfields.Count, failures)
			failures = 0
		}
	}

	ticker := time.NewTicker(raInterval)
	defer ticker.Stop()

	send() // advertise immediately so the peer converges quickly
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			send()
		}
	}
}

// solicitReader answers Router Solicitations with an immediate unicast RA so a
// peer that just came up doesn't wait for the next periodic advertisement.
func solicitReader(ctx context.Context, conn *ndp.Conn, ra *ndp.RouterAdvertisement, logger *slog.Logger, ifname string) {
	for {
		if ctx.Err() != nil {
			return
		}
		if err := conn.SetReadDeadline(time.Now().Add(raReadTimeout)); err != nil {
			return
		}
		msg, _, from, err := conn.ReadFrom()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				continue // just a poll timeout; re-check ctx
			}
			if errors.Is(err, net.ErrClosed) {
				// The socket was dropped so it can be re-opened; the
				// replacement gets its own reader.
				return
			}
			if ctx.Err() != nil {
				return
			}
			continue
		}
		if _, ok := msg.(*ndp.RouterSolicitation); ok {
			if err := conn.WriteTo(ra, nil, from); err != nil {
				logger.Debug("Failed to answer router solicitation",
					logfields.Interface, ifname, logfields.Error, err)
			}
		}
	}
}
