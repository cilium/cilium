package server

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
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

	// Some default values
	defaultMultiplier = 3
	defaultRxInterval = 1000 * time.Millisecond
	defaultTxInterval = 1000 * time.Millisecond
)

type bfdPeerStats struct {
	rxPacket             atomic.Uint64
	txPacket             atomic.Uint64
	txDrop               atomic.Uint64
	txError              atomic.Uint64
	invalidDiscriminator atomic.Uint64
	expired              atomic.Uint64
}

type bfdPeer struct {
	peerState   peerState
	logger      *slog.Logger
	peerAddress netip.Addr
	peerPort    int

	udpClient *net.UDPConn

	expiryInterval time.Duration

	state             atomic.Int32
	myDiscriminator   uint32
	yourDiscriminator uint32
	multiplier        uint8
	rxInterval        time.Duration
	txInterval        time.Duration

	eventStart    *time.Ticker
	eventRxPacket chan *bfd.BFDHeader
	eventTx       *time.Ticker
	eventExpiry   *time.Ticker
	eventShutdown chan struct{}
	shutdownOnce  sync.Once
	shutdownWait  sync.WaitGroup
	stopped       atomic.Bool

	stats bfdPeerStats
}

func NewBfdPeer(ps peerState, logger *slog.Logger, peerAddress netip.Addr, config oc.BfdConfig) *bfdPeer {
	peerPort := int(config.Port)
	if peerPort == 0 {
		peerPort = BfdServerPort
	}

	p := &bfdPeer{
		peerState:   ps,
		logger:      logger,
		peerAddress: peerAddress,
		peerPort:    peerPort,

		myDiscriminator: randomBFDMyDiscriminator(),
		multiplier:      defaultMultiplier,
		rxInterval:      defaultRxInterval,
		txInterval:      defaultTxInterval,

		eventStart:    time.NewTicker(time.Second),
		eventRxPacket: make(chan *bfd.BFDHeader, 1),
		eventShutdown: make(chan struct{}),
	}

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_DOWN))

	if config.DetectionMultiplier > 0 {
		p.multiplier = config.DetectionMultiplier
	}

	if config.RequiredMinimumReceive > 0 {
		p.rxInterval = time.Duration(config.RequiredMinimumReceive) * time.Microsecond
	}

	if config.DesiredMinimumTxInterval > 0 {
		p.txInterval = time.Duration(config.DesiredMinimumTxInterval) * time.Microsecond
	}

	p.expiryInterval = time.Duration(p.multiplier) * p.rxInterval
	p.eventTx = time.NewTicker(p.txInterval)

	p.eventExpiry = time.NewTicker(p.expiryInterval)
	p.eventExpiry.Stop()

	p.shutdownWait.Add(1)
	go p.loop()
	return p
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
		case <-p.eventShutdown:
			p.shutdown()
			return
		}
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
// (fe80::…%iface, as used by unnumbered single-hop BFD per RFC 5881) can be reached — dialing a
// link-local address without its zone fails.
func (p *bfdPeer) remoteUDPAddr() *net.UDPAddr {
	return &net.UDPAddr{
		IP:   p.peerAddress.AsSlice(),
		Zone: p.peerAddress.Zone(),
		Port: p.peerPort,
	}
}

func (p *bfdPeer) startClient() {
	localAddress := &net.UDPAddr{
		Port: randRange(bfdSourcePortMin, bfdSourcePortMax),
	}

	remoteAddress := p.remoteUDPAddr()

	var err error
	p.udpClient, err = net.DialUDP("udp", localAddress, remoteAddress)
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

	// https://datatracker.ietf.org/doc/html/rfc5881
	//   If BFD authentication is not in use on a session, all BFD Control
	//   packets for the session MUST be sent with a Time to Live (TTL) or Hop
	//   Limit value of 255
	err = netutils.SetUDPTTLSockopt(p.udpClient, 255)
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

func (p *bfdPeer) rxPacket(h *bfd.BFDHeader) {
	if h.YourDiscriminator != 0 && h.YourDiscriminator != p.myDiscriminator {
		p.stats.invalidDiscriminator.Add(1)
		return
	}

	p.stats.rxPacket.Add(1)

	// NOTE: remote DesiredMinTxInterval and RequiredMinRxInterval ignored

	switch h.State {
	case bfd.StateAdminDown:
		if p.sessionState() != api.BfdSessionState_BFD_SESSION_STATE_DOWN {
			p.remoteDown()
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
}

func (p *bfdPeer) tx() {
	switch p.sessionState() {
	case api.BfdSessionState_BFD_SESSION_STATE_UP:
		p.sendPacket(bfd.StateUp, false, false, p.yourDiscriminator)
	case api.BfdSessionState_BFD_SESSION_STATE_INIT:
		p.sendPacket(bfd.StateInit, false, false, p.yourDiscriminator)
	default:
		p.sendPacket(bfd.StateDown, false, false, 0)
	}
}

func (p *bfdPeer) expiry() {
	p.logger.Warn("Expired",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.stats.expired.Add(1)

	p.resetPeer()
	p.setStateDown()
}

func (p *bfdPeer) shutdown() {
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

	p.resetPeer()
	p.setStateDown()
}

func (p *bfdPeer) resetPeer() {
	if err := p.peerState.ResetPeer(context.Background(), &api.ResetPeerRequest{
		Address:       p.peerAddress.String(),
		Communication: "BFD is down",
		Soft:          false,
	}); err != nil {
		p.logger.Warn("ResetPeer failed",
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
		State:                 state,
		Poll:                  poll,
		Final:                 final,
		DetectTimeMultiplier:  p.multiplier,
		MyDiscriminator:       p.myDiscriminator,
		YourDiscriminator:     yourDiscriminator,
		DesiredMinTxInterval:  uint32(p.txInterval.Microseconds()),
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

func (p *bfdPeer) setStateDown() {
	p.logger.Debug("Set state to DOWN",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_DOWN))
	p.yourDiscriminator = 0

	p.eventExpiry.Stop()
}

func (p *bfdPeer) setStateInit(yourDiscriminator uint32) {
	p.logger.Debug("Set state to INIT",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_INIT))
	p.yourDiscriminator = yourDiscriminator
}

func (p *bfdPeer) setStateUp(yourDiscriminator uint32) {
	p.logger.Debug("Set state to UP",
		slog.String("Topic", "bfd"),
		slog.String("Peer", p.peerAddress.String()),
	)

	p.state.Store(int32(api.BfdSessionState_BFD_SESSION_STATE_UP))
	p.yourDiscriminator = yourDiscriminator

	p.eventExpiry.Reset(p.expiryInterval)

	// send poll packet
	p.sendPacket(bfd.StateUp, true, false, yourDiscriminator)
}
