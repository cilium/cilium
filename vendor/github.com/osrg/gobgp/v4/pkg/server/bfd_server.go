// This is partial implementation of BFD protocol (https://datatracker.ietf.org/doc/html/rfc5880)
// only for fast detection of connection failures between BGP peers.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bfd"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type bfdServerStats struct {
	rxPacket      atomic.Uint64
	rxDrop        atomic.Uint64
	rxError       atomic.Uint64
	invalidPacket atomic.Uint64
	unknownPeer   atomic.Uint64
}

type bfdEventPeerUpdate struct {
	isAdd         bool
	peerAddress   netip.Addr
	config        oc.BfdConfig
	localAddress  netip.Addr
	bindInterface string
	minTTL        int
	done          chan struct{}
}

// bfdRxInfo describes how a BFD control packet was received. Fields read
// from ancillary data are left at their unknown value when the platform
// does not report them.
type bfdRxInfo struct {
	// src is the source of the packet. A link-local address keeps its zone.
	src netip.AddrPort
	// dst is the destination address of the packet. Invalid if unknown.
	dst netip.Addr
	// ifIndex is the index of the interface the packet came in on. 0 if
	// unknown.
	ifIndex int
	// ttl is the TTL or Hop Limit of the packet. -1 if the socket can't
	// report it. 0 if the socket reports it but the packet came without it.
	ttl int
	// mhop is true when the packet came in on the multihop port.
	mhop bool
}

// bfdListener is one receive socket of the BFD server: one address family
// on one UDP port. IPv4 and IPv6 use separate sockets so that each one
// reports the TTL or Hop Limit through its own ancillary data.
type bfdListener struct {
	network string // "udp4" or "udp6"
	mhop    bool   // listens on the multihop port

	conn *net.UDPConn
	read func(b []byte) (int, bfdRxInfo, error)

	// failed is true when the last attempt to open the socket failed.
	// Only the first failure in a row is logged at Error level.
	failed bool
}

func newBfdListeners() []*bfdListener {
	return []*bfdListener{
		{network: "udp4"},
		{network: "udp6"},
		{network: "udp4", mhop: true},
		{network: "udp6", mhop: true},
	}
}

type bfdPeerState struct {
	peerAddress netip.Addr
	state       api.BfdPeerState
}

type peerState interface {
	// bfdDown closes the BGP session with the peer at addr because the
	// BFD session went down.
	bfdDown(ctx context.Context, addr netip.Addr) error
}

type bfdServer struct {
	peerState peerState
	logger    *slog.Logger

	config *oc.BfdConfig

	listeners       []*bfdListener
	listenInterface string
	// multihopPort is the UDP port of the multihop listeners. Tests
	// replace it.
	multihopPort uint16

	// peers and discrs index the same sessions, by peer address and by
	// local discriminator. Both are protected by peersMutex.
	peersMutex sync.RWMutex
	peers      map[netip.Addr]*bfdPeer
	discrs     map[uint32]*bfdPeer

	// randomDiscriminator returns a random nonzero discriminator. Tests
	// replace it.
	randomDiscriminator func() uint32

	eventStartStop  *time.Ticker
	eventConfig     chan *oc.BfdConfig
	eventPeerUpdate chan *bfdEventPeerUpdate
	eventShutdown   chan struct{}
	shutdownOnce    sync.Once
	stopped         atomic.Bool

	shutdownWait sync.WaitGroup

	serverStop chan struct{}
	serverWait sync.WaitGroup

	stats bfdServerStats
}

func NewBfdServer(ps peerState, logger *slog.Logger) *bfdServer {
	s := &bfdServer{
		peerState: ps,
		logger:    logger,

		peers:               make(map[netip.Addr]*bfdPeer),
		discrs:              make(map[uint32]*bfdPeer),
		randomDiscriminator: randomBFDMyDiscriminator,

		listeners:    newBfdListeners(),
		multihopPort: bfdMultihopPort,

		eventStartStop:  time.NewTicker(time.Second),
		eventConfig:     make(chan *oc.BfdConfig, 1),
		eventPeerUpdate: make(chan *bfdEventPeerUpdate, 1),
		eventShutdown:   make(chan struct{}),
	}

	s.shutdownWait.Add(1)
	go s.loop()
	return s
}

func (s *bfdServer) Start(ctx context.Context, config oc.BfdConfig) error {
	if s.stopped.Load() {
		return errors.New("bfd server stopped")
	}

	select {
	case s.eventConfig <- &config:
		if s.stopped.Load() {
			return errors.New("bfd server stopped")
		}

		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.eventShutdown:
		return errors.New("bfd server stopped")
	}
}

func (s *bfdServer) Stop() {
	s.shutdownOnce.Do(func() {
		s.stopped.Store(true)
		close(s.eventShutdown)
		s.shutdownWait.Wait()
	})
}

func (s *bfdServer) AddPeer(ctx context.Context, peerAddress netip.Addr, config oc.BfdConfig, bindInterface string) error {
	return s.addPeer(ctx, peerAddress, config, netip.Addr{}, bindInterface, 1)
}

// addPeer adds a session. minTTL is the lowest TTL or Hop Limit a received
// packet of a multihop session may have. It is not used for a single-hop
// session.
func (s *bfdServer) addPeer(ctx context.Context, peerAddress netip.Addr, config oc.BfdConfig, localAddress netip.Addr, bindInterface string, minTTL int) error {
	if s.stopped.Load() {
		return errors.New("bfd server stopped")
	}

	if !config.Enabled {
		return nil
	}

	done := make(chan struct{})
	select {
	case s.eventPeerUpdate <- &bfdEventPeerUpdate{isAdd: true, peerAddress: peerAddress, config: config, localAddress: localAddress, bindInterface: bindInterface, minTTL: minTTL, done: done}:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.eventShutdown:
		return errors.New("bfd server stopped")
	}
	// Replacement must finish retiring the old session before the caller can
	// release the BGP lock and allow queued management operations to execute.
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.eventShutdown:
		return errors.New("bfd server stopped")
	}
}

func (s *bfdServer) DeletePeer(ctx context.Context, peerAddress netip.Addr) error {
	if s.stopped.Load() {
		return errors.New("bfd server stopped")
	}

	done := make(chan struct{})
	select {
	case s.eventPeerUpdate <- &bfdEventPeerUpdate{isAdd: false, peerAddress: peerAddress, done: done}:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.eventShutdown:
		return errors.New("bfd server stopped")
	}
	// Retirement includes cancellation of any pending BFD-down operation. Do not
	// let a new session start while an operation belonging to the old one is still live.
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-s.eventShutdown:
		return errors.New("bfd server stopped")
	}
}

func (s *bfdServer) GetPeerState(peerAddress netip.Addr) (*bfdPeerState, error) {
	state := s.getPeerState(peerAddress)
	if state == nil {
		return nil, errors.New("peer not found")
	}
	return state, nil
}

func (s *bfdServer) GetPeerStateList() []*bfdPeerState {
	return s.getPeerStateList()
}

func (s *bfdServer) GetServerStats() *api.BfdState {
	return &api.BfdState{
		ReceivedPacket: s.stats.rxPacket.Load(),
		ReceivedDrop:   s.stats.rxDrop.Load(),
		ReceivedError:  s.stats.rxError.Load(),
		InvalidPacket:  s.stats.invalidPacket.Load(),
		UnknownPeer:    s.stats.unknownPeer.Load(),
	}
}

func (s *bfdServer) loop() {
	defer s.shutdownWait.Done()

	for {
		select {
		case <-s.eventStartStop.C:
			success := true

			s.peersMutex.RLock()
			peersLen := len(s.peers)
			s.peersMutex.RUnlock()

			if peersLen > 0 {
				success = s.start()
			} else {
				s.stop()
			}

			if success {
				s.eventStartStop.Stop()
			}
		case ev := <-s.eventConfig:
			s.config = ev
		case ev := <-s.eventPeerUpdate:
			if ev.isAdd {
				s.addBfdPeer(ev.peerAddress, ev.config, ev.localAddress, ev.bindInterface, ev.minTTL)
			} else {
				s.deleteBfdPeer(ev.peerAddress)
			}
			if ev.done != nil {
				close(ev.done)
			}

			s.eventStartStop.Reset(time.Second)
		case <-s.eventShutdown:
			s.shutdown()
			return
		}
	}
}

// start opens the receive sockets that are not open yet. It returns true
// when all of them are open. A socket that cannot be opened does not stop
// the others; the caller retries it later.
func (s *bfdServer) start() bool {
	if s.config == nil {
		// BFD server not configured
		return false
	}

	ok := true
	for _, l := range s.listeners {
		if l.conn == nil && !s.startListener(l) {
			ok = false
		}
	}
	return ok
}

func (s *bfdServer) startListener(l *bfdListener) bool {
	port := s.config.Port
	if l.mhop {
		port = s.multihopPort
	}
	addressString := ":" + strconv.FormatUint(uint64(port), 10)

	var lc net.ListenConfig
	lc.Control = func(network, address string, sc syscall.RawConn) error {
		if s.listenInterface != "" {
			s.logger.Info("binding bfd listener to interface", slog.String("interface", s.listenInterface))
			if err := netutils.SetBindToDevSockopt(sc, s.listenInterface); err != nil {
				return err
			}
		}

		return netutils.SetReuseAddrSockopt(sc)
	}

	pc, err := lc.ListenPacket(context.Background(), l.network, addressString)
	if err != nil {
		s.listenFailed(l, "Can't listen UDP", addressString, err)
		return false
	}

	conn, ok := pc.(*net.UDPConn)
	if !ok {
		_ = pc.Close()
		s.listenFailed(l, "Unexpected connection listener", addressString, nil)
		return false
	}

	l.conn = conn
	l.failed = false
	if l.network == "udp4" {
		l.read = s.ipv4Reader(conn, l.mhop)
	} else {
		l.read = s.ipv6Reader(conn, l.mhop)
	}

	s.logger.Info("BFD server is started",
		slog.String("Topic", "bfd"),
		slog.String("Network", l.network),
		slog.String("Address", addressString),
		slog.Bool("Multihop", l.mhop),
	)

	if s.serverStop == nil {
		s.serverStop = make(chan struct{})
	}
	s.serverWait.Add(1)
	go s.serverLoop(l.read, s.serverStop)
	return true
}

// listenFailed logs a failure to open a receive socket. A host without
// IPv6 fails the same way on every retry, so only the first failure in a
// row is logged at Error level.
func (s *bfdServer) listenFailed(l *bfdListener, msg, address string, err error) {
	level := slog.LevelError
	if l.failed {
		level = slog.LevelDebug
	}
	l.failed = true

	attrs := []slog.Attr{
		slog.String("Topic", "bfd"),
		slog.String("Network", l.network),
		slog.String("Address", address),
	}
	if err != nil {
		attrs = append(attrs, slog.Any("Error", err))
	}
	s.logger.LogAttrs(context.Background(), level, msg, attrs...)
}

// setControlMessage enables one kind of ancillary data on a receive socket.
// A failure only leaves the matching bfdRxInfo field unknown, so it is
// logged and the socket is used anyway.
func (s *bfdServer) setControlMessage(network, what string, set func() error) bool {
	if err := set(); err != nil {
		s.logger.Warn("Can't enable ancillary data on BFD socket",
			slog.String("Topic", "bfd"),
			slog.String("Network", network),
			slog.String("Data", what),
			slog.Any("Error", err),
		)
		return false
	}
	return true
}

func (s *bfdServer) ipv4Reader(conn *net.UDPConn, mhop bool) func([]byte) (int, bfdRxInfo, error) {
	pc := ipv4.NewPacketConn(conn)
	ttlOK := s.setControlMessage("udp4", "TTL", func() error {
		return pc.SetControlMessage(ipv4.FlagTTL, true)
	})
	s.setControlMessage("udp4", "destination and interface", func() error {
		return pc.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	})

	return func(b []byte) (int, bfdRxInfo, error) {
		n, cm, src, err := pc.ReadFrom(b)
		if err != nil {
			return 0, bfdRxInfo{}, err
		}
		info := newBfdRxInfo(src)
		info.mhop = mhop
		if ttlOK {
			// Every packet should carry the value. One without it
			// gets 0, so the TTL check discards it.
			info.ttl = 0
		}
		if cm != nil {
			if ttlOK {
				info.ttl = cm.TTL
			}
			info.dst = ipToAddr(cm.Dst)
			info.ifIndex = cm.IfIndex
		}
		return n, info, nil
	}
}

func (s *bfdServer) ipv6Reader(conn *net.UDPConn, mhop bool) func([]byte) (int, bfdRxInfo, error) {
	pc := ipv6.NewPacketConn(conn)
	ttlOK := s.setControlMessage("udp6", "Hop Limit", func() error {
		return pc.SetControlMessage(ipv6.FlagHopLimit, true)
	})
	s.setControlMessage("udp6", "destination and interface", func() error {
		return pc.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	})

	return func(b []byte) (int, bfdRxInfo, error) {
		n, cm, src, err := pc.ReadFrom(b)
		if err != nil {
			return 0, bfdRxInfo{}, err
		}
		info := newBfdRxInfo(src)
		info.mhop = mhop
		if ttlOK {
			// Every packet should carry the value. One without it
			// gets 0, so the TTL check discards it.
			info.ttl = 0
		}
		if cm != nil {
			if ttlOK {
				info.ttl = cm.HopLimit
			}
			info.dst = ipToAddr(cm.Dst)
			info.ifIndex = cm.IfIndex
		}
		return n, info, nil
	}
}

func newBfdRxInfo(src net.Addr) bfdRxInfo {
	info := bfdRxInfo{ttl: -1}
	if u, ok := src.(*net.UDPAddr); ok {
		// A udp4 socket reports the source as a 16-byte IPv4-mapped address.
		ap := u.AddrPort()
		info.src = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return info
}

func ipToAddr(ip net.IP) netip.Addr {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func (s *bfdServer) stop() {
	if s.serverStop == nil {
		return
	}

	close(s.serverStop)
	for _, l := range s.listeners {
		if l.conn != nil {
			l.conn.Close()
		}
	}
	s.serverWait.Wait()
	for _, l := range s.listeners {
		l.conn = nil
		l.read = nil
		l.failed = false
	}
	s.serverStop = nil

	s.logger.Info("BFD server is stopped",
		slog.String("Topic", "bfd"),
	)
}

func (s *bfdServer) addBfdPeer(peerAddress netip.Addr, config oc.BfdConfig, localAddress netip.Addr, bindInterface string, minTTL int) {
	s.peersMutex.RLock()
	existing, ok := s.peers[peerAddress]
	s.peersMutex.RUnlock()

	if ok {
		peerPort := int(config.Port)
		if peerPort == 0 {
			peerPort = BfdServerPort
		}
		if existing.localAddress == localAddress && existing.bindInterface == bindInterface &&
			existing.multihop == config.Multihop && existing.minTTL == minTTL && existing.peerPort == peerPort {
			s.logger.Debug("BFD peer already exist",
				slog.String("Topic", "bfd"),
				slog.String("Peer", peerAddress.String()),
			)

			// The timers can change without a new session (RFC 5880 Section
			// 6.8.3).
			existing.updateConfig(config)
			return
		}
		// A changed source, interface or session type replaces the session;
		// retirement cancels its pending BFD-down operation so it cannot
		// affect the replacement.
		s.deleteBfdPeer(peerAddress)
	}

	bfdPeer := newBfdPeer(s.peerState, s.logger, peerAddress, config, localAddress, bindInterface, s.newDiscriminator(), minTTL)
	if bfdPeer != nil {
		s.logger.Info("Insert BFD peer",
			slog.String("Topic", "bfd"),
			slog.String("Peer", peerAddress.String()),
		)

		s.peersMutex.Lock()
		s.peers[peerAddress] = bfdPeer
		s.discrs[bfdPeer.myDiscriminator] = bfdPeer
		s.peersMutex.Unlock()
	}
}

// newDiscriminator returns a random local discriminator that no session
// uses. RFC 5880 Section 6.8.1 says bfd.LocalDiscr "MUST be unique across
// all BFD sessions on this system, and nonzero. It SHOULD be set to a
// random (but still unique) value to improve security." Only the loop
// goroutine adds sessions, so the value stays unused until it is
// inserted.
func (s *bfdServer) newDiscriminator() uint32 {
	s.peersMutex.RLock()
	defer s.peersMutex.RUnlock()

	for {
		d := s.randomDiscriminator()
		if _, ok := s.discrs[d]; !ok {
			return d
		}
	}
}

func (s *bfdServer) deleteBfdPeer(peerAddress netip.Addr) {
	s.peersMutex.RLock()
	peer, ok := s.peers[peerAddress]
	s.peersMutex.RUnlock()

	if !ok {
		s.logger.Debug("Unknown BFD peer",
			slog.String("Topic", "bfd"),
			slog.String("Peer", peerAddress.String()),
		)

		return
	}

	s.peersMutex.Lock()
	delete(s.peers, peerAddress)
	delete(s.discrs, peer.myDiscriminator)
	s.peersMutex.Unlock()
	peer.Stop()

	s.logger.Info("Remove BFD peer",
		slog.String("Topic", "bfd"),
		slog.String("Peer", peerAddress.String()),
	)
}

func (s *bfdServer) getPeerState(address netip.Addr) *bfdPeerState {
	s.peersMutex.RLock()
	peer, ok := s.peers[address]
	s.peersMutex.RUnlock()

	if !ok {
		return nil
	}

	return &bfdPeerState{
		peerAddress: peer.peerAddress,
		state: api.BfdPeerState{
			SessionState: api.BfdSessionState(peer.state.Load()),
			BfdAsync: &api.BfdAsyncCounters{
				ReceivedPackets:    peer.stats.rxPacket.Load(),
				TransmittedPackets: peer.stats.txPacket.Load(),
			},
		},
	}
}

func (s *bfdServer) getPeerStateList() []*bfdPeerState {
	s.peersMutex.RLock()
	list := make([]*bfdPeerState, 0, len(s.peers))
	for _, peer := range s.peers {
		list = append(list, &bfdPeerState{
			peerAddress: peer.peerAddress,
			state: api.BfdPeerState{
				SessionState: api.BfdSessionState(peer.state.Load()),
				BfdAsync: &api.BfdAsyncCounters{
					ReceivedPackets:    peer.stats.rxPacket.Load(),
					TransmittedPackets: peer.stats.txPacket.Load(),
				},
			},
		})
	}
	s.peersMutex.RUnlock()

	return list
}

func (s *bfdServer) shutdown() {
	s.peersMutex.Lock()
	peers := make([]*bfdPeer, 0, len(s.peers))
	for address, peer := range s.peers {
		peers = append(peers, peer)
		delete(s.peers, address)
		delete(s.discrs, peer.myDiscriminator)
	}
	s.peersMutex.Unlock()

	for _, peer := range peers {
		peer.Stop()
	}

	s.stop()
	s.eventStartStop.Stop()
}

func (s *bfdServer) serverLoop(read func([]byte) (int, bfdRxInfo, error), stop <-chan struct{}) {
	defer s.serverWait.Done()

	// buffer size must be more than BFD Control Packet size
	buffer := make([]byte, 4096)
	for {
		length, info, err := read(buffer)
		if err != nil {
			select {
			case <-stop:
				return
			default:
				s.stats.rxError.Add(1)
			}

			continue
		}

		bfdPacket := &bfd.BFDHeader{}
		err = bfdPacket.UnmarshalBinary(buffer[:length])
		if err != nil {
			s.logger.Debug("Invalid packet",
				slog.String("Topic", "bfd"),
				slog.Any("Error", err),
			)

			s.stats.invalidPacket.Add(1)
			continue
		}

		s.rxPacket(info, bfdPacket)
	}
}

func (s *bfdServer) rxPacket(info bfdRxInfo, packet *bfd.BFDHeader) {
	if reason := invalidPacketReason(packet); reason != "" {
		s.logger.Debug("Invalid packet",
			slog.String("Topic", "bfd"),
			slog.Any("Peer", info.src.Addr()),
			slog.String("Reason", reason),
		)

		s.stats.invalidPacket.Add(1)
		return
	}

	peer := s.lookupPeer(info, packet)
	if peer == nil {
		s.logger.Debug("Unknown BFD peer",
			slog.String("Topic", "bfd"),
			slog.Any("Peer", info.src.Addr()),
			slog.Uint64("YourDiscriminator", uint64(packet.YourDiscriminator)),
		)

		s.stats.unknownPeer.Add(1)
		return
	}

	if !peer.validTTL(info.ttl) {
		s.logger.Debug("Invalid TTL",
			slog.String("Topic", "bfd"),
			slog.String("Peer", peer.peerAddress.String()),
			slog.Int("TTL", info.ttl),
		)

		peer.stats.invalidTTL.Add(1)
		return
	}

	if !peer.Rx(packet) {
		s.stats.rxDrop.Add(1)
		return
	}

	s.stats.rxPacket.Add(1)
}

// invalidPacketReason returns why a received packet must be discarded
// before a session is looked up, or "" if it need not be. RFC 5880 Section
// 6.8.6 says:
//
//	If the version number is not correct (1), the packet MUST be
//	discarded.
//
//	If the Multipoint (M) bit is nonzero, the packet MUST be
//	discarded.
//
//	If the A bit is set and no authentication is in use (bfd.AuthType
//	is zero), the packet MUST be discarded.
//
// GoBGP does not support BFD authentication, so no session uses it. The A
// bit check therefore does not depend on the session, and is done here
// with the others. The length is checked when the packet is parsed. The
// Detect Mult and My Discriminator checks are done by the session.
func invalidPacketReason(packet *bfd.BFDHeader) string {
	switch {
	case packet.Version != 1:
		return "version is not 1"
	case packet.Multipoint:
		return "Multipoint bit is set"
	case packet.AuthPresent:
		return "Authentication Present bit is set"
	}
	return ""
}

// validTTL checks the TTL or Hop Limit of a received packet of the
// session. A socket that can't report the TTL gives -1, and the check is
// skipped.
func (p *bfdPeer) validTTL(ttl int) bool {
	if ttl == -1 {
		return true
	}
	if p.multihop {
		return ttl >= p.minTTL
	}
	// RFC 5881 Section 5: "All received BFD Control packets that are
	// demultiplexed to the session MUST be discarded if the received TTL
	// or Hop Limit is not equal to 255." GoBGP does not support BFD
	// authentication, so this applies to every single-hop session.
	return ttl == bfdTTL
}

// lookupPeer finds the session of a received packet as RFC 5880 Section
// 6.8.6 describes:
//
//	If the Your Discriminator field is nonzero, it MUST be used to
//	select the session with which this BFD packet is associated. If
//	no session is found, the packet MUST be discarded.
//
// The source address is not checked in that case. For a point-to-point
// link, RFC 5881 Section 6 says that subsequent packets "MUST be
// demultiplexed solely by the Your Discriminator field (as is always the
// case). This allows the source address to change if necessary."
//
// With a zero Your Discriminator, the session is selected by the peer
// address. The destination address must also match the local address
// when both are known. The session itself discards a zero Your
// Discriminator in a state other than Down or AdminDown.
//
// In both cases, the session must be of the type of the port the packet
// came in on. RFC 5881 Section 4 says "BFD Control packets MUST be
// transmitted in UDP packets with destination port 3784", and RFC 5883
// Section 5 says that for multihop "the UDP destination port MUST have a
// value of 4784". Without this check, a packet sent to the multihop port
// would skip the TTL 255 check of a single-hop session.
func (s *bfdServer) lookupPeer(info bfdRxInfo, packet *bfd.BFDHeader) *bfdPeer {
	s.peersMutex.RLock()
	defer s.peersMutex.RUnlock()

	var peer *bfdPeer
	if packet.YourDiscriminator != 0 {
		peer = s.discrs[packet.YourDiscriminator]
	} else {
		peer = s.peers[info.src.Addr()]
		if peer != nil && !peer.localMatches(info.dst) {
			peer = nil
		}
	}
	if peer == nil || peer.multihop != info.mhop {
		return nil
	}
	return peer
}

// localMatches reports whether dst, the destination of a received packet,
// can be the local address of the session. It can when either one is
// unknown.
func (p *bfdPeer) localMatches(dst netip.Addr) bool {
	local := p.localAddress.WithZone("").Unmap()
	dst = dst.WithZone("").Unmap()
	return !local.IsValid() || local.IsUnspecified() || !dst.IsValid() || local == dst
}
