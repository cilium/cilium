package server

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bfd"
)

const (
	// https://datatracker.ietf.org/doc/html/rfc5881
	//   The source port MUST be in the range 49152 through 65535
	bfdSourcePortMin = 49152
	bfdSourcePortMax = 65535

	// TTL or Hop Limit of sent and received BFD Control packets. See
	// startClient and bfdServer.rxPacket for the RFC text.
	bfdTTL = 255

	// Some default values
	defaultMultiplier = 3
	defaultRxInterval = 1000 * time.Millisecond
	defaultTxInterval = 1000 * time.Millisecond

	// https://datatracker.ietf.org/doc/html/rfc5880#section-6.8.3
	//   When bfd.SessionState is not Up, the system MUST set
	//   bfd.DesiredMinTxInterval to a value of not less than one second
	//   (1,000,000 microseconds).
	bfdSlowTxInterval = time.Second
)

type bfdPeerStats struct {
	rxPacket             atomic.Uint64
	txPacket             atomic.Uint64
	txDrop               atomic.Uint64
	txError              atomic.Uint64
	invalidDiscriminator atomic.Uint64
	invalidMultiplier    atomic.Uint64
	invalidTTL           atomic.Uint64
	expired              atomic.Uint64
}

type bfdPeer struct {
	peerState     peerState
	logger        *slog.Logger
	peerAddress   netip.Addr
	peerPort      int
	localAddress  netip.Addr
	bindInterface string
	// multihop is true for a multihop session (RFC 5883). minTTL is the
	// lowest TTL or Hop Limit of a received packet of such a session.
	multihop bool
	minTTL   int

	udpClient *net.UDPConn

	expiryInterval time.Duration

	state             atomic.Int32
	myDiscriminator   uint32
	yourDiscriminator uint32
	// localDiag is the RFC's bfd.LocalDiag: the reason for the last change
	// of the session state, sent in the Diag field. Confined to the peer's
	// loop goroutine.
	localDiag  bfd.DiagnosticType
	multiplier uint8
	rxInterval time.Duration
	txInterval time.Duration

	// desiredMinTx is the RFC's bfd.DesiredMinTxInterval: the value advertised in
	// transmitted packets and one of the two terms of the transmit interval (see
	// effectiveTxInterval). txInterval is the configured value, which changes only
	// through applyConfig. Confined to the peer's loop goroutine, or to NewBfdPeer
	// before that goroutine starts -- same discipline as
	// yourDiscriminator/expiryInterval, so no atomics.
	desiredMinTx time.Duration
	// remoteDetectMult and remoteDesiredMinTx are the peer's Detect Mult and Desired
	// Min TX Interval from its last packet, the remote terms of the Detection Time
	// (see detectionTime). Same confinement as desiredMinTx.
	remoteDetectMult   uint8
	remoteDesiredMinTx time.Duration
	// heldTxInterval and heldRxInterval keep the previous bfd.DesiredMinTxInterval
	// and bfd.RequiredMinRxInterval while a Poll Sequence announces a change that
	// RFC 5880 Section 6.8.3 does not let take effect before the sequence ends: an
	// increase of bfd.DesiredMinTxInterval while Up keeps the old transmit
	// interval, and a reduction of bfd.RequiredMinRxInterval while Up keeps the old
	// value in the Detection Time. Zero when nothing is held. Same confinement as
	// desiredMinTx.
	heldTxInterval time.Duration
	heldRxInterval time.Duration
	// remoteMinRxInterval is the RFC's bfd.RemoteMinRxInterval (Section 6.8.1): the
	// peer's advertised Required Min RX Interval, the other term of the transmit
	// interval. Same confinement as desiredMinTx.
	remoteMinRxInterval time.Duration
	// lastTx is when tx() last ran (peer creation time until the first run). It
	// anchors the pacing deadline; see armTx. Same confinement as desiredMinTx.
	lastTx time.Time
	// txJitterPct is the percentage of the transmit interval that the next periodic
	// packet waits after lastTx, drawn once per transmission by drawTxJitter and
	// fixed until the next one, so the pacing deadline is a pure function of lastTx
	// and the transmit interval (see armTx). Same confinement as desiredMinTx.
	txJitterPct int
	// pollSequence is true while a Poll Sequence is in flight: the P bit is set on
	// periodic transmissions until a Final is received. Same confinement as desiredMinTx.
	pollSequence bool
	// pollSettling is true from the Final that terminates a Poll Sequence until a
	// packet with the Final bit clear is received. A bool carries no sequence
	// identity, so a late Final answering a Poll of the sequence that just ended
	// would terminate a new one early and release its held values (see
	// heldTxInterval). RFC 5880 Section 6.8.3 offers waiting for that packet as one
	// way to tell the two apart, so a configuration change waits for it, and for
	// any sequence in flight, before it starts its own (see applyNextConfig). Same
	// confinement as desiredMinTx.
	pollSettling bool

	// nextConfig is a configuration handed over by updateConfig and not yet
	// applied by the loop goroutine. eventConfig wakes the loop up for it.
	nextConfig  atomic.Pointer[oc.BfdConfig]
	eventConfig chan struct{}

	eventStart    *time.Ticker
	eventRxPacket chan *bfd.BFDHeader
	eventTx       *time.Timer
	eventExpiry   *time.Ticker
	eventShutdown chan struct{}
	shutdownOnce  sync.Once
	shutdownWait  sync.WaitGroup
	stopped       atomic.Bool
	resetCtx      context.Context
	cancelReset   context.CancelFunc

	stats bfdPeerStats
}

func NewBfdPeer(ps peerState, logger *slog.Logger, peerAddress netip.Addr, config oc.BfdConfig, bindInterface string) *bfdPeer {
	return newBfdPeer(ps, logger, peerAddress, config, netip.Addr{}, bindInterface, randomBFDMyDiscriminator(), 1)
}

// newBfdPeer creates a session. myDiscriminator must be nonzero and must not
// be used by any other session; see bfdServer.newDiscriminator.
func newBfdPeer(ps peerState, logger *slog.Logger, peerAddress netip.Addr, config oc.BfdConfig, localAddress netip.Addr, bindInterface string, myDiscriminator uint32, minTTL int) *bfdPeer {
	peerPort := int(config.Port)
	if peerPort == 0 {
		peerPort = BfdServerPort
	}

	p := &bfdPeer{
		peerState:     ps,
		logger:        logger,
		peerAddress:   peerAddress,
		peerPort:      peerPort,
		localAddress:  localAddress,
		bindInterface: bindInterface,
		multihop:      config.Multihop,
		minTTL:        minTTL,

		myDiscriminator: myDiscriminator,
		// RFC 5880 Section 6.8.1: bfd.RemoteMinRxInterval MUST be initialized
		// to 1. Not the Go zero value: zero stops periodic transmission (see
		// armTx).
		remoteMinRxInterval: time.Microsecond,

		eventStart:    time.NewTicker(time.Second),
		eventRxPacket: make(chan *bfd.BFDHeader, 1),
		eventShutdown: make(chan struct{}),
		eventConfig:   make(chan struct{}, 1),
	}

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_DOWN))

	p.multiplier, p.rxInterval, p.txInterval = bfdTimers(config)

	p.expiryInterval = time.Duration(p.multiplier) * p.rxInterval

	// The session starts Down, so the 6.8.3 floor applies from construction. This is
	// the initial value, not a change, so set it directly rather than through
	// setDesiredMinTx: there is no Poll Sequence to initiate for it.
	p.desiredMinTx = max(p.txInterval, bfdSlowTxInterval)
	p.lastTx = time.Now()
	p.drawTxJitter()
	p.eventTx = time.NewTimer(p.jitteredTxInterval())

	p.eventExpiry = time.NewTicker(p.expiryInterval)
	p.eventExpiry.Stop()

	p.resetCtx, p.cancelReset = context.WithCancel(context.Background())
	p.shutdownWait.Add(1)
	go p.loop()
	return p
}

// bfdTimers returns the detection multiplier, bfd.RequiredMinRxInterval and the
// configured transmit interval of config, with the defaults for unset values.
func bfdTimers(config oc.BfdConfig) (uint8, time.Duration, time.Duration) {
	multiplier := uint8(defaultMultiplier)
	if config.DetectionMultiplier > 0 {
		multiplier = config.DetectionMultiplier
	}
	rxInterval := defaultRxInterval
	if config.RequiredMinimumReceive > 0 {
		rxInterval = time.Duration(config.RequiredMinimumReceive) * time.Microsecond
	}
	txInterval := defaultTxInterval
	if config.DesiredMinimumTxInterval > 0 {
		txInterval = time.Duration(config.DesiredMinimumTxInterval) * time.Microsecond
	}
	return multiplier, rxInterval, txInterval
}

// updateConfig hands the session new timer settings: the detection multiplier,
// the Desired Min TX Interval and the Required Min RX Interval. The other
// settings need a new session; see bfdServer.addBfdPeer. It does not wait for
// the loop goroutine, which may be waiting for the BGP lock held by our caller
// (see Stop). The loop applies the latest settings handed over.
func (p *bfdPeer) updateConfig(config oc.BfdConfig) {
	p.nextConfig.Store(&config)
	select {
	case p.eventConfig <- struct{}{}:
	default:
	}
}

func (p *bfdPeer) Rx(packet *bfd.BFDHeader) bool {
	if p.stopped.Load() {
		return false
	}

	select {
	case p.eventRxPacket <- packet:
		return true
	case <-p.eventShutdown:
		return false
	default:
		return false
	}
}

func (p *bfdPeer) Stop() {
	p.shutdownOnce.Do(func() {
		p.stopped.Store(true)
		// A BFD-down operation may be waiting for the BGP lock held by our lifecycle caller.
		// Cancel it before waiting for the BFD loop, including its queued operation.
		p.cancelReset()
		close(p.eventShutdown)
		p.shutdownWait.Wait()
	})
}

func (p *bfdPeer) loop() {
	defer p.shutdownWait.Done()

	for {
		select {
		case <-p.eventStart.C:
			success := p.start()
			if success {
				p.eventStart.Stop()
			}
		case bfdPacket := <-p.eventRxPacket:
			p.rxPacket(bfdPacket)
		case <-p.eventTx.C:
			p.tx()
		case <-p.eventExpiry.C:
			p.expiry()
		case <-p.eventConfig:
		case <-p.eventShutdown:
			p.shutdown()
			return
		}
		// Any event may be the one that lets a waiting configuration apply.
		p.applyNextConfig()
	}
}

func (p *bfdPeer) start() bool {
	if p.udpClient == nil {
		p.startClient()
	}

	return p.udpClient != nil
}

func (p *bfdPeer) stop() {
	if p.udpClient == nil {
		return
	}

	err := p.udpClient.Close()
	if err != nil {
		p.logger.Warn("Can't close UDP",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
		)
	}

	p.udpClient = nil

	p.logger.Debug("BFD client is stopped",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)
}

// remoteUDPAddr builds the BFD peer's UDP address. The zone is preserved so a link-local peer
// (fe80::...%iface, as used by unnumbered single-hop BFD per RFC 5881) can be reached -- dialing a
// link-local address without its zone fails.
func (p *bfdPeer) remoteUDPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   p.peerAddress.AsSlice(),
		Zone: p.peerAddress.Zone(),
		Port: p.peerPort,
	}
}

func (p *bfdPeer) localUDPAddr() *net.UDPAddr {
	addr := &net.UDPAddr{
		Port: randRange(bfdSourcePortMin, bfdSourcePortMax),
	}

	if p.localAddress.IsValid() && !p.localAddress.IsUnspecified() {
		addr.IP = p.localAddress.AsSlice()
		addr.Zone = p.localAddress.Zone()
	}

	return addr
}

func (p *bfdPeer) startClient() {
	localAddress := p.localUDPAddr()

	remoteAddress := p.remoteUDPAddr()

	var err error

	dialer := net.Dialer{
		LocalAddr: localAddress,
		Control: func(network, address string, c syscall.RawConn) error {
			if p.bindInterface != "" {
				return netutils.SetBindToDevSockopt(c, p.bindInterface)
			}

			return nil
		},
	}

	conn, err := dialer.Dial("udp", remoteAddress.String())
	if err != nil {
		p.logger.Warn("Can't dial UDP",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
			slog.String("LocalAddress", localAddress.String()),
			slog.String("RemoteAddress", remoteAddress.String()),
			slog.Any("Error", err),
		)

		return
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		p.logger.Warn("Can't dial UDP",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
			slog.String("LocalAddress", localAddress.String()),
			slog.String("RemoteAddress", remoteAddress.String()),
			slog.Any("Error", "connection is not a UDP connection"),
		)

		return
	}

	p.udpClient = udpConn

	// https://datatracker.ietf.org/doc/html/rfc5881
	//   If BFD authentication is not in use on a session, all BFD Control
	//   packets for the session MUST be sent with a Time to Live (TTL) or Hop
	//   Limit value of 255
	err = netutils.SetUDPTTLSockopt(p.udpClient, bfdTTL)
	if err != nil {
		p.logger.Error("Can't set TTL to 255",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
			slog.String("LocalAddress", localAddress.String()),
			slog.String("RemoteAddress", remoteAddress.String()),
			slog.Any("Error", err),
		)

		err = p.udpClient.Close()
		if err != nil {
			p.logger.Warn("Can't close UDP",
				slog.String("Topic", "bfd"),
				slog.String("Peer", p.peerAddress.String()),
			)
		}

		p.udpClient = nil
		return
	}

	p.logger.Debug("BFD client is started",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
		slog.String("LocalAddress", localAddress.String()),
		slog.String("RemoteAddress", remoteAddress.String()),
	)
}

// effectiveTxInterval is the interval GoBGP actually transmits at.
//
// RFC 5880 Section 6.8.7: a system MUST NOT transmit BFD Control packets at an
// interval less than the larger of bfd.DesiredMinTxInterval and
// bfd.RemoteMinRxInterval. desiredMinTx carries the Section 6.8.3 not-Up floor,
// so the floor reaches the pacing through it. While an increase of desiredMinTx
// is held (see heldTxInterval), the previous value is used.
func (p *bfdPeer) effectiveTxInterval() time.Duration {
	desiredMinTx := p.desiredMinTx
	if p.heldTxInterval != 0 {
		desiredMinTx = p.heldTxInterval
	}
	return max(desiredMinTx, p.remoteMinRxInterval)
}

// detectionTime is the Detection Time of RFC 5880 Section 6.8.4: the remote
// Detect Mult multiplied by the negotiated receive interval, i.e. the greater
// of our bfd.RequiredMinRxInterval and the remote Desired Min TX Interval.
// While a reduction of bfd.RequiredMinRxInterval is held (see heldRxInterval),
// the previous value is used.
func (p *bfdPeer) detectionTime() time.Duration {
	rxInterval := p.rxInterval
	if p.heldRxInterval != 0 {
		rxInterval = p.heldRxInterval
	}
	return time.Duration(p.remoteDetectMult) * max(rxInterval, p.remoteDesiredMinTx)
}

// armTx re-arms the transmit timer at the absolute pacing deadline
// lastTx + jitteredTxInterval, or transmits at once if that deadline has
// already passed. It runs after every received packet, because the packet may
// have changed bfd.RemoteMinRxInterval and with it the transmit interval.
//
// The deadline is a pure function of the last transmission, the jitter drawn
// with it, and the current transmit interval. Anchoring on the last
// transmission rather than on the present instant is what keeps the pacing
// safe against a peer that floods packets or flaps its advertised value:
// repeated calls converge on the same deadline instead of pushing it out, so
// the deadline moves only when a requirement changes, never by mere packet
// arrival. Reusing the jitter drawn in tx() is part of that. A fresh draw per
// call would make the packet go out at the smallest draw seen since the last
// transmission, so under a stream of received packets the cadence would sink
// toward the 75% floor and the transmit rate would follow the peer's receive
// rate, which is the coupling the jitter exists to break.
//
// When the deadline has already passed, RFC 5880 Section 6.8.3 requires the
// next packet "as soon as practicable". Sending it here does not starve either:
// tx() moves lastTx to now and re-arms a full period, so the anchor advances
// with every send and a flood can trigger at most one immediate transmission
// per interval. Re-arming from the present instant without sending is the
// design that starves, because that anchor never advances. Go 1.23+ timer
// semantics mean Reset discards any expiry already pending, so an overdue
// receive landing on a fire cannot produce two packets.
//
// RFC 5880 Section 6.8.7: "A system MUST NOT periodically transmit BFD
// Control packets if bfd.RemoteMinRxInterval is zero." The timer is then
// stopped. A packet sent at a state change, or a Final sent in reply to a
// Poll, is not periodic and still goes out. A later packet with a nonzero
// value starts the timer again.
func (p *bfdPeer) armTx() {
	if p.remoteMinRxInterval == 0 {
		p.eventTx.Stop()
		return
	}
	remaining := time.Until(p.lastTx.Add(p.jitteredTxInterval()))
	if remaining <= 0 {
		p.tx()
		return
	}
	p.eventTx.Reset(remaining)
}

func (p *bfdPeer) rxPacket(h *bfd.BFDHeader) {
	// RFC 5880 Section 6.8.6: if the Detect Mult field is zero, the packet
	// MUST be discarded.
	if h.DetectTimeMultiplier == 0 {
		p.stats.invalidMultiplier.Add(1)
		return
	}

	// RFC 5880 Section 6.8.6: if the My Discriminator field is zero, the
	// packet MUST be discarded.
	if h.MyDiscriminator == 0 {
		p.stats.invalidDiscriminator.Add(1)
		return
	}

	// RFC 5880 Section 6.8.6: a nonzero Your Discriminator selects the
	// session and MUST match ours. A zero Your Discriminator carries no
	// session binding, so it is only accepted from a remote system that has
	// not learned our discriminator yet, i.e. one in Down or AdminDown.
	if h.YourDiscriminator != 0 {
		if h.YourDiscriminator != p.myDiscriminator {
			p.stats.invalidDiscriminator.Add(1)
			return
		}
	} else {
		if h.State != bfd.StateDown && h.State != bfd.StateAdminDown {
			p.stats.invalidDiscriminator.Add(1)
			return
		}

		// Once the remote discriminator is bound, a packet that omits Your
		// Discriminator still has to come from that same remote system, or
		// it can tear the session down without ever having seen it.
		if p.yourDiscriminator != 0 && h.MyDiscriminator != p.yourDiscriminator {
			p.stats.invalidDiscriminator.Add(1)
			return
		}
	}

	p.stats.rxPacket.Add(1)

	// RFC 5880 Section 6.8.6: "If a Poll Sequence is being transmitted by the local
	// system and the Final (F) bit in the received packet is set, the Poll Sequence
	// MUST be terminated." Section 6.8.6 lists this before the state processing,
	// and so must this function: a Final ends the sequence that was in flight when
	// the packet arrived, never one that the packet's own state transition starts.
	// The values held for the sequence are released here, before the Detection
	// Time below, so this packet already uses the new one.
	if h.Final {
		if p.pollSequence {
			p.pollSequence = false
			p.heldTxInterval = 0
			p.heldRxInterval = 0
			p.pollSettling = true
		}
	} else {
		p.pollSettling = false
	}

	p.remoteDetectMult = h.DetectTimeMultiplier
	p.remoteDesiredMinTx = time.Duration(h.DesiredMinTxInterval) * time.Microsecond
	p.expiryInterval = p.detectionTime()

	// RFC 5880 Section 6.8.6: "Set bfd.RemoteMinRxInterval to the value of
	// Required Min RX Interval." A zero stops periodic transmission (see
	// armTx). The timer is re-armed once at the end of this function, after
	// the state machine has run.
	p.remoteMinRxInterval = time.Duration(h.RequiredMinRxInterval) * time.Microsecond

	switch h.State {
	case bfd.StateAdminDown:
		// RFC 5882 Sections 3.2 and 4.2: AdminDown means the remote system took
		// the session down administratively, not that the path failed. BGP has
		// its own liveness detection, so the BGP session is left alone; only the
		// BFD session goes Down.
		if p.sessionState() != api.BfdSessionState_BFD_SESSION_STATE_DOWN {
			p.logger.Info("Remote peer signaled BFD admin down",
				slog.String("Topic", "bfd"),
				slog.String("Peer", p.peerAddress.String()),
			)

			// RFC 5880 Section 6.8.6: "Set bfd.LocalDiag to 3 (Neighbor
			// signaled session down)".
			p.setStateDown(bfd.DiagnosticNeighborSignaledSessionDown)
		}
	case bfd.StateDown:
		switch p.sessionState() {
		case api.BfdSessionState_BFD_SESSION_STATE_DOWN:
			p.setStateInit(h.MyDiscriminator)
		case api.BfdSessionState_BFD_SESSION_STATE_UP:
			p.remoteDown()
		}
	case bfd.StateInit:
		switch p.sessionState() {
		case api.BfdSessionState_BFD_SESSION_STATE_DOWN, api.BfdSessionState_BFD_SESSION_STATE_INIT:
			p.setStateUp(h.MyDiscriminator)
		}
	case bfd.StateUp:
		if p.sessionState() == api.BfdSessionState_BFD_SESSION_STATE_INIT {
			p.setStateUp(h.MyDiscriminator)
		}
	}

	if h.Poll {
		p.sendPacket(p.sessionStateToWire(), false, true, h.MyDiscriminator)
	}

	if p.sessionState() == api.BfdSessionState_BFD_SESSION_STATE_INIT ||
		p.sessionState() == api.BfdSessionState_BFD_SESSION_STATE_UP {
		p.eventExpiry.Reset(p.expiryInterval)
	}

	// The peer's advertised requirement may have moved the transmit interval.
	// Re-arm here, after the state machine, so an overdue transmission goes out
	// carrying the state this packet left us in, not the one it found us in. A
	// state transition above has already transmitted and re-armed through tx();
	// armTx then computes that same deadline, so the second call is harmless.
	p.armTx()
}

// drawTxJitter draws the random reduction of the transmit interval for the next
// periodic BFD Control packet, as the percentage of the interval kept in
// txJitterPct. It is drawn once per transmission, in tx(), and reused by every
// jitteredTxInterval call until the next one: the reduction belongs to a packet,
// not to each re-computation of that packet's deadline (see armTx).
//
// RFC 5880 Section 6.8.7: the transmit interval MUST be reduced per packet
// by a random value of 0 to 25%; when the detect multiplier is 1, the
// interval MUST be no more than 90% and no less than 75% of the negotiated
// interval.
func (p *bfdPeer) drawTxJitter() {
	maxPct := 100
	if p.multiplier == 1 {
		maxPct = 90
	}
	p.txJitterPct = randRange(75, maxPct)
}

// jitteredTxInterval returns the interval between the last periodic BFD Control
// packet and the next: the transmit interval (effectiveTxInterval) less the
// reduction drawn for this packet by drawTxJitter. Between transmissions it
// changes only when the transmit interval does.
func (p *bfdPeer) jitteredTxInterval() time.Duration {
	return p.effectiveTxInterval() * time.Duration(p.txJitterPct) / 100
}

// tx sends the periodic BFD Control packet for the current state, draws the
// jitter for the next one, and re-arms the transmit timer from this moment. It
// runs on every timer fire, from armTx when the pacing deadline is already
// overdue, and from the state setters on every state transition. RFC 5880
// Section 6.8.7: a packet whose contents would differ from the previously
// transmitted one SHOULD be transmitted between the periodic transmissions, to
// communicate a change in state more rapidly. Sending that packet through here
// makes it the new pacing anchor, so the periodic schedule restarts from the
// change instead of adding a packet on top of it. Between runs, armTx moves the
// deadline only to lastTx + jitteredTxInterval, which changes only when one of
// the interval's terms does.
func (p *bfdPeer) tx() {
	p.lastTx = time.Now()
	p.drawTxJitter()
	if p.remoteMinRxInterval == 0 {
		// No periodic packets (see armTx).
		p.eventTx.Stop()
	} else {
		p.eventTx.Reset(p.jitteredTxInterval())
	}

	switch p.sessionState() {
	case api.BfdSessionState_BFD_SESSION_STATE_UP:
		p.sendPacket(bfd.StateUp, p.pollSequence, false, p.yourDiscriminator)
	case api.BfdSessionState_BFD_SESSION_STATE_INIT:
		p.sendPacket(bfd.StateInit, p.pollSequence, false, p.yourDiscriminator)
	default:
		p.sendPacket(bfd.StateDown, p.pollSequence, false, 0)
	}
}

func (p *bfdPeer) expiry() {
	if p.sessionState() == api.BfdSessionState_BFD_SESSION_STATE_DOWN {
		p.eventExpiry.Stop()
		return
	}

	p.logger.Warn("Expired",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.stats.expired.Add(1)

	// Only an Up session that expires is a path failure. A session that
	// expires in Init never came up. RFC 5882 Section 3.3 says: "The BFD
	// state machine transitions that occur in the process of bringing up a
	// BFD session in such situations SHOULD NOT cause a connectivity failure
	// notification to the clients." We read the expiry in Init as such a
	// transition. FRR and BIRD also reset BGP only on Up to Down.
	if p.sessionState() == api.BfdSessionState_BFD_SESSION_STATE_UP {
		p.bfdDown()
	}
	// RFC 5880 Section 6.8.4: "the local system MUST set bfd.SessionState to
	// Down and bfd.LocalDiag to 1 (Control Detection Time Expired)."
	p.setStateDown(bfd.DiagnosticControlDetectionTimeExpired)
}

func (p *bfdPeer) shutdown() {
	// RFC 5880 Section 6.8.16: a disabled session goes to AdminDown, so the remote
	// can tell it from a path failure and keep its clients up (RFC 5882 Section
	// 3.2). The RFC asks for packets for a Detection Time; one is sent, as FRR
	// does, so that removing a peer does not wait that long. A remote that holds
	// no session with us has nothing to be told.
	if p.yourDiscriminator != 0 {
		p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_ADMIN_DOWN))
		p.localDiag = bfd.DiagnosticAdministrativelyDown
		p.sendPacket(bfd.StateAdminDown, false, false, p.yourDiscriminator)
	}

	p.stop()
	p.eventStart.Stop()
	p.eventTx.Stop()
	p.eventExpiry.Stop()
}

func (p *bfdPeer) remoteDown() {
	p.logger.Warn("Remote peer signaled BFD down",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.bfdDown()
	// RFC 5880 Section 6.8.6: "Set bfd.LocalDiag to 3 (Neighbor signaled
	// session down)".
	p.setStateDown(bfd.DiagnosticNeighborSignaledSessionDown)
}

func (p *bfdPeer) bfdDown() {
	if err := p.peerState.bfdDown(p.resetCtx, p.peerAddress); err != nil && !errors.Is(err, context.Canceled) {
		// Cancellation is the retiring session withdrawing its own BFD-down operation.
		p.logger.Warn("failed to close BGP session on BFD down",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
			slog.String("Err", err.Error()),
		)
	}
}

func (p *bfdPeer) sendPacket(state bfd.StateType, poll bool, final bool, yourDiscriminator uint32) {
	if p.udpClient == nil {
		p.stats.txDrop.Add(1)
		return
	}

	packet := &bfd.BFDHeader{
		Version:               1,
		Diagnostic:            p.localDiag,
		State:                 state,
		Poll:                  poll,
		Final:                 final,
		DetectTimeMultiplier:  p.multiplier,
		MyDiscriminator:       p.myDiscriminator,
		YourDiscriminator:     yourDiscriminator,
		DesiredMinTxInterval:  uint32(p.desiredMinTx.Microseconds()),
		RequiredMinRxInterval: uint32(p.rxInterval.Microseconds()),
	}

	buffer, err := packet.MarshalBinary()
	if err != nil {
		// should never happen
		p.logger.Error("MarshalBinary",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
		)
		return
	}

	_, err = p.udpClient.Write(buffer)
	if err != nil {
		p.logger.Debug("Can't send UDP packet",
			slog.String("Topic", "bfd"),
			slog.String("Peer", p.peerAddress.String()),
		)

		p.stats.txError.Add(1)
		return
	}

	p.stats.txPacket.Add(1)
}

func (p *bfdPeer) sessionState() api.BfdSessionState {
	return api.BfdSessionState(p.state.Load())
}

func (p *bfdPeer) sessionStateToWire() bfd.StateType {
	switch p.sessionState() {
	case api.BfdSessionState_BFD_SESSION_STATE_UP:
		return bfd.StateUp
	case api.BfdSessionState_BFD_SESSION_STATE_INIT:
		return bfd.StateInit
	case api.BfdSessionState_BFD_SESSION_STATE_ADMIN_DOWN:
		return bfd.StateAdminDown
	default:
		return bfd.StateDown
	}
}

// setDesiredMinTx applies a change to bfd.DesiredMinTxInterval and initiates the Poll
// Sequence that RFC 5880 Section 6.8.3 requires for it, provided there is a remote
// session to poll. Without a remote discriminator there is none: that change is the
// transition to Down, and a Down packet with the Poll bit set and a zero Your
// Discriminator would ask a system that holds no session with us for a Final, and keep
// asking until one arrived, which it never does when the far end is not running BFD.
// The sequence's purpose (Section 6.5: confirm that the remote has seen the new timing
// before we rely on it) does not apply to a session that has just been torn down. The
// Down state itself tells the remote all it needs.
//
// The new interval is advertised at once. An increase made while the session is Up
// does not take effect before the sequence ends (Section 6.8.3); applyConfig holds
// the old one for that. The timer is not touched here: every change comes from a
// state transition or from applyConfig, and both transmit it at once through tx(),
// which re-arms the timer.
func (p *bfdPeer) setDesiredMinTx(d time.Duration) {
	if d == p.desiredMinTx {
		return
	}
	p.desiredMinTx = d
	if p.yourDiscriminator != 0 {
		p.pollSequence = true
	}
}

// setStateDown moves the session to Down. diag is the reason, kept in
// bfd.LocalDiag.
func (p *bfdPeer) setStateDown(diag bfd.DiagnosticType) {
	p.logger.Debug("Set state to DOWN",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_DOWN))
	p.yourDiscriminator = 0
	p.localDiag = diag

	// The remote session is gone, and with it any Poll Sequence in flight: nobody is
	// left to answer it, and Down packets with the Poll bit set would ask an unbound
	// peer for a Final (see setDesiredMinTx).
	p.pollSequence = false
	p.pollSettling = false
	p.heldTxInterval = 0
	p.heldRxInterval = 0

	// RFC 5880 Section 6.8.3: "When bfd.SessionState is not Up, the system MUST set
	// bfd.DesiredMinTxInterval to a value of not less than one second (1,000,000
	// microseconds)."
	p.setDesiredMinTx(max(p.txInterval, bfdSlowTxInterval))

	p.eventExpiry.Stop()

	// Transmit the state change at once (RFC 5880 Section 6.8.7; see tx).
	p.tx()
}

func (p *bfdPeer) setStateInit(yourDiscriminator uint32) {
	p.logger.Debug("Set state to INIT",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_INIT))
	p.yourDiscriminator = yourDiscriminator
	// RFC 5880 does not say when bfd.LocalDiag is cleared. Like BIRD, clear
	// it when the session moves to Init or Up; FRR clears it on Up.
	p.localDiag = bfd.DiagnosticNoDiagnostic

	// desiredMinTx is left untouched here: Init is only ever entered from Down
	// (rxPacket's bfd.StateDown case), and Down already carries the RFC 5880 Section
	// 6.8.3 not-Up floor, which still applies.

	// Transmit the state change at once (RFC 5880 Section 6.8.7; see tx).
	p.tx()
}

func (p *bfdPeer) setStateUp(yourDiscriminator uint32) {
	p.logger.Debug("Set state to UP",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_UP))
	p.yourDiscriminator = yourDiscriminator
	p.localDiag = bfd.DiagnosticNoDiagnostic

	// RFC 5880 Section 6.8.3: Up lifts the not-Up floor, restoring the configured
	// interval, a change that starts a Poll Sequence unless it is a no-op.
	p.setDesiredMinTx(p.txInterval)

	p.eventExpiry.Reset(p.expiryInterval)

	// Transmit the state change at once (RFC 5880 Section 6.8.7; see tx). This packet
	// is also the first to carry the restored interval and the Poll bit, so the
	// sequence starts now rather than at the end of the Down cadence.
	p.tx()
}

// applyNextConfig applies a configuration handed over by updateConfig, unless a
// Poll Sequence is in flight or has only just ended (see pollSettling): the
// change may need a sequence of its own, and RFC 5880 Section 6.8.3 does not
// allow two at once. The loop calls it after every event, so a waiting
// configuration applies as soon as that is over. nextConfig is cleared only
// after the configuration is applied, and only if no newer one was handed over
// meanwhile; that one applies next.
func (p *bfdPeer) applyNextConfig() {
	if p.pollSequence || p.pollSettling {
		return
	}
	config := p.nextConfig.Load()
	if config == nil {
		return
	}
	p.applyConfig(*config)
	p.nextConfig.CompareAndSwap(config, nil)
}

// applyConfig changes the timer settings of a running session without affecting
// its state, as RFC 5880 Section 6.8.3 allows: "The time values used to
// determine BFD packet transmission intervals and the session Detection Time may
// be modified at any time without affecting the state of the session."
//
// A change of bfd.DesiredMinTxInterval or bfd.RequiredMinRxInterval initiates a
// Poll Sequence, as Section 6.8.3 requires, and both are sent in one packet so
// that the Final answers them together. A change of the detection multiplier
// needs none; the peer takes it from the next packet. While Up, an increase of
// bfd.DesiredMinTxInterval keeps the previous transmit interval, and a reduction
// of bfd.RequiredMinRxInterval keeps the previous Detection Time, until the
// sequence ends. Any other change takes effect at once.
func (p *bfdPeer) applyConfig(config oc.BfdConfig) {
	multiplier, rxInterval, txInterval := bfdTimers(config)
	if multiplier == p.multiplier && rxInterval == p.rxInterval && txInterval == p.txInterval {
		return
	}

	up := p.sessionState() == api.BfdSessionState_BFD_SESSION_STATE_UP
	desiredMinTx := txInterval
	if !up {
		// RFC 5880 Section 6.8.3: the not-Up floor (see setStateDown).
		desiredMinTx = max(txInterval, bfdSlowTxInterval)
	}
	if up && desiredMinTx > p.desiredMinTx {
		p.heldTxInterval = p.desiredMinTx
	}
	if up && rxInterval < p.rxInterval {
		p.heldRxInterval = p.rxInterval
	}

	rxChanged := rxInterval != p.rxInterval
	p.multiplier = multiplier
	p.rxInterval = rxInterval
	p.txInterval = txInterval
	p.setDesiredMinTx(desiredMinTx)
	if rxChanged && p.yourDiscriminator != 0 {
		p.pollSequence = true
	}

	if p.remoteDetectMult != 0 {
		p.expiryInterval = p.detectionTime()
		if p.sessionState() == api.BfdSessionState_BFD_SESSION_STATE_INIT || up {
			p.eventExpiry.Reset(p.expiryInterval)
		}
	}

	// Transmit the new values at once (RFC 5880 Section 6.8.7; see tx).
	p.tx()
}
