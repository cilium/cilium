// Copyright (C) 2014-2021 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/eapache/channels"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/internal/pkg/version"
	"github.com/osrg/gobgp/v4/pkg/config/oc"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
)

const (
	minConnectRetryInterval = 2
)

type fsmStateReasonType uint8

const (
	fsmDying fsmStateReasonType = iota
	fsmAdminDown
	fsmReadFailed
	fsmWriteFailed
	fsmNotificationSent
	fsmNotificationRecv
	fsmHoldTimerExpired
	fsmIdleTimerExpired
	fsmRestartTimerExpired
	fsmGracefulRestart
	fsmInvalidMsg
	fsmNewConnection
	fsmOpenMsgReceived
	fsmOpenMsgNegotiated
	fsmHardReset
	fsmDeConfigured
	fsmBadPeerAS
)

type fsmStateReason struct {
	Type            fsmStateReasonType
	BGPNotification *bgp.BGPMessage
	Data            []byte
}

func newfsmStateReason(typ fsmStateReasonType, notif *bgp.BGPMessage, data []byte) *fsmStateReason {
	return &fsmStateReason{
		Type:            typ,
		BGPNotification: notif,
		Data:            data,
	}
}

func (r fsmStateReason) String() string {
	switch r.Type {
	case fsmDying:
		return "dying"
	case fsmAdminDown:
		return "admin-down"
	case fsmReadFailed:
		return "read-failed"
	case fsmWriteFailed:
		return "write-failed"
	case fsmNotificationSent:
		body := r.BGPNotification.Body.(*bgp.BGPNotification)
		return fmt.Sprintf("notification-sent %s", bgp.NewNotificationErrorCode(body.ErrorCode, body.ErrorSubcode).String())
	case fsmNotificationRecv:
		body := r.BGPNotification.Body.(*bgp.BGPNotification)
		return fmt.Sprintf("notification-received %s", bgp.NewNotificationErrorCode(body.ErrorCode, body.ErrorSubcode).String())
	case fsmHoldTimerExpired:
		return "hold-timer-expired"
	case fsmIdleTimerExpired:
		return "idle-hold-timer-expired"
	case fsmRestartTimerExpired:
		return "restart-timer-expired"
	case fsmGracefulRestart:
		return "graceful-restart"
	case fsmInvalidMsg:
		return "invalid-msg"
	case fsmNewConnection:
		return "new-connection"
	case fsmOpenMsgReceived:
		return "open-msg-received"
	case fsmOpenMsgNegotiated:
		return "open-msg-negotiated"
	case fsmHardReset:
		return "hard-reset"
	case fsmBadPeerAS:
		return "bad-peer-as"
	default:
		return "unknown"
	}
}

type fsmMsgType int

const (
	_ fsmMsgType = iota
	fsmMsgStateChange
	fsmMsgBGPMessage
)

type fsmMsg struct {
	MsgType     fsmMsgType
	MsgData     any
	handling    bgp.ErrorHandling
	StateReason *fsmStateReason
	timestamp   time.Time
	payload     []byte
}

type fsmOutgoingMsg struct {
	Paths []*table.Path
}

const (
	holdtimeOpensent = 240
	holdtimeIdle     = 5
)

type adminState int32

const (
	adminStateUp adminState = iota
	adminStateDown
	adminStatePfxCt
)

func (s adminState) String() string {
	switch s {
	case adminStateUp:
		return "adminStateUp"
	case adminStateDown:
		return "adminStateDown"
	case adminStatePfxCt:
		return "adminStatePfxCt"
	default:
		return "Unknown"
	}
}

type adminStateOperation struct {
	State         adminState
	Communication []byte
}

type fsmState struct {
	val atomic.Int32
}

func (s *fsmState) String() string {
	return s.Load().String()
}

func (s *fsmState) Load() bgp.FSMState {
	return bgp.FSMState(s.val.Load())
}

func (s *fsmState) Store(state bgp.FSMState) {
	s.val.Store(int32(state))
}

type adminStateRaw struct {
	val atomic.Int32
}

func (s *adminStateRaw) String() string {
	return s.Load().String()
}

func (s *adminStateRaw) Load() adminState {
	return adminState(s.val.Load())
}

func (s *adminStateRaw) Store(state adminState) {
	s.val.Store(int32(state))
}

func (s *adminStateRaw) CompareAndSwap(old, new adminState) bool {
	return s.val.CompareAndSwap(int32(old), int32(new))
}

func initializeConn(fsm *fsm, conn net.Conn) {
	if err := setPeerConnTTL(fsm, conn); err != nil {
		fsm.logger.Warn("cannot set TTL",
			slog.String("State", fsm.state.String()),
			slog.String("Error", err.Error()))
	}
	if err := setPeerConnMSS(fsm, conn); err != nil {
		fsm.logger.Warn("cannot set MSS",
			slog.String("State", fsm.state.String()),
			slog.String("Error", err.Error()))
	}
	if err := setPeerConnTOS(fsm, conn); err != nil {
		fsm.logger.Warn("cannot set TOS",
			slog.String("State", fsm.state.String()),
			slog.String("Error", err.Error()))
	}
}

type outgoingConn struct {
	conn net.Conn
	open *bgp.BGPMessage
}

type outgoingConnManager struct {
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	fsm    *fsm
	state  fsmState
}

func newOutGoingConnManager(ctx context.Context, fsm *fsm) *outgoingConnManager {
	cctx, cancel := context.WithCancel(ctx)
	ocm := &outgoingConnManager{
		ctx:    cctx,
		cancel: cancel,
		fsm:    fsm,
	}
	ocm.state.Store(bgp.BGP_FSM_CONNECT)
	ocm.wg.Add(1)
	go ocm.run(fsm.outgoingConnCh)

	return ocm
}

func (ocm *outgoingConnManager) run(ch chan<- outgoingConn) {
	defer func() {
		ocm.wg.Done()
		ocm.cancel()
	}()

	fsm := ocm.fsm
	conf := fsm.pConf.ReadOnly()
	isPassive := conf.Transport.Config.PassiveMode

	if isPassive {
		return
	}

	var conn net.Conn
	for {
		switch ocm.state.Load() {
		case bgp.BGP_FSM_CONNECT:
			conn = ocm.fsm.h.connectLoop(ocm.ctx)
			if ocm.ctx.Err() != nil {
				// right after connectLoop() returns a connection, the context may be canceled.
				if conn != nil {
					conn.Close()
				}
				return
			}

			fsm.lock.Lock()
			initializeConn(fsm, conn)
			conf := fsm.pConf.ReadCopy()
			open := buildopen(fsm.gConf, &conf)
			fsm.pConf.Update(&conf)
			fsm.lock.Unlock()
			b, _ := open.Serialize()

			conn.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write(b); err != nil {
				conn.Close()
				continue
			}
			fsm.bgpMessageStateUpdate(bgp.BGP_MSG_OPEN, false)
			fsm.logger.Debug("outgoing connection established")
			ocm.state.Store(bgp.BGP_FSM_OPENSENT)
		case bgp.BGP_FSM_OPENSENT:
			recvCh := make(chan *fsmMsg, 1)
			reasonCh := make(chan fsmStateReason, 1)
			var wg sync.WaitGroup
			wg.Add(1)
			holdTimer := time.NewTimer(time.Second * time.Duration(fsm.opensentHoldTime))
			go ocm.fsm.h.recvMessage(ocm.ctx, conn, recvCh, reasonCh, &wg)
			select {
			case <-holdTimer.C:
				fsm.logger.Debug("outgoing connection closing due to hold timer expired in OPEN SENT state")
				notif := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil)
				// sendNotification closes the connection
				_ = fsm.sendNotification(conn, notif)
				wg.Wait()
				ocm.state.Store(bgp.BGP_FSM_CONNECT)
				continue
			case <-ocm.ctx.Done():
				holdTimer.Stop()
				conn.SetReadDeadline(time.Now())
				conn.Close()
				wg.Wait()
				return
			case reason := <-reasonCh:
				holdTimer.Stop()
				fsm.logger.Debug("outgoing connection IO error", slog.String("reason", reason.String()))
				conn.Close()
				wg.Wait()
				ocm.state.Store(bgp.BGP_FSM_CONNECT)
				continue
			case fmsg := <-recvCh:
				holdTimer.Stop()
				wg.Wait()
				nextState, _, notif := ocm.fsm.handleOpen(fmsg)
				if nextState != bgp.BGP_FSM_OPENCONFIRM {
					if notif != nil {
						_ = fsm.sendNotification(conn, notif)
					} else {
						conn.Close()
					}
					ocm.state.Store(bgp.BGP_FSM_CONNECT)
					continue
				}
				fsm.logger.Debug("open message received on outgoing connection", slog.String("remote", conn.RemoteAddr().String()))
				ch <- outgoingConn{
					conn: conn,
					open: fmsg.MsgData.(*bgp.BGPMessage),
				}
				return
			}
		default:
			panic("outgoing connection manager got invalid fsm state")
		}
	}
}

func (ocm *outgoingConnManager) stop() {
	ocm.cancel()
	ocm.wg.Wait()
	// drain
	for {
		select {
		case c := <-ocm.fsm.outgoingConnCh:
			c.conn.Close()
		default:
			return
		}
	}
}

type pConfAccess struct {
	conf atomic.Pointer[oc.Neighbor]
}

func (p *pConfAccess) ReadOnly() *oc.Neighbor {
	return p.conf.Load()
}

func (p *pConfAccess) ReadCopy() oc.Neighbor {
	pConf := p.conf.Load()
	conf := *pConf
	conf.AfiSafis = make([]oc.AfiSafi, len(conf.AfiSafis))
	copy(conf.AfiSafis, pConf.AfiSafis)

	conf.State.SupportedCapabilitiesList = make([]oc.BgpCapability, len(pConf.State.SupportedCapabilitiesList))
	copy(conf.State.SupportedCapabilitiesList, pConf.State.SupportedCapabilitiesList)
	conf.State.RemoteCapabilityList = make([]bgp.ParameterCapabilityInterface, len(pConf.State.RemoteCapabilityList))
	copy(conf.State.RemoteCapabilityList, pConf.State.RemoteCapabilityList)
	conf.State.LocalCapabilityList = make([]bgp.ParameterCapabilityInterface, len(pConf.State.LocalCapabilityList))
	copy(conf.State.LocalCapabilityList, pConf.State.LocalCapabilityList)
	return conf
}

// store needs to be called under fsm.lock.Lock()
func (p *pConfAccess) Update(conf *oc.Neighbor) {
	p.conf.Store(conf)
}

type fsm struct {
	counterStats oc.Messages
	timerStats   oc.Timers

	lock  sync.Mutex
	gConf *oc.Global
	// mostly read config
	// config state messages statistics and timers state UpdateRecvTime are atomic
	pConf pConfAccess

	capMap   map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface
	recvOpen *bgp.BGPMessage

	// safe for concurrent access
	state                    fsmState
	familyMap                atomic.Value // map[bgp.Family]bgp.BGPAddPathMode
	rtcEORWait               atomic.Bool
	logger                   *slog.Logger
	gracefulRestartTimer     *time.Timer
	outgoingCh               *channels.InfiniteChannel
	notification             chan *bgp.BGPMessage
	deconfiguredNotification chan *bgp.BGPMessage
	connCh                   chan net.Conn
	adminState               adminStateRaw
	adminStateCh             chan adminStateOperation
	outgoingConnCh           chan outgoingConn

	// only loop goroutine accesses; no lock required
	outgoingConnMgr   *outgoingConnManager
	idleHoldTime      float64
	opensentHoldTime  float64 // imutable
	twoByteAsTrans    bool
	isEBGP            bool
	isConfed          bool
	isTreatAsWithdraw bool

	// multiple fsm goroutines access. no lock required due to how they are used.
	conn net.Conn
	h    *fsmHandler
}

func (fsm *fsm) tryReceiveOutgoingConn() (outgoingConn, bool) {
	select {
	case item := <-fsm.outgoingConnCh:
		return item, true
	default:
		var zero outgoingConn
		return zero, false
	}
}

// resolveCollision resolves connection collision according to RFC 4271 Section 6.8
// and RFC 6286 Section 2.3.
// Returns true if active connection should be used, false if passive connection should be used.
func (fsm *fsm) isDominant(open *bgp.BGPOpen) bool {
	fsm.lock.Lock()
	myID := fsm.gConf.Config.RouterId
	myAS := fsm.pConf.ReadOnly().Config.LocalAs
	fsm.lock.Unlock()

	localIDbin := myID.As4()
	localID := binary.BigEndian.Uint32(localIDbin[:])
	remoteIDbin := open.ID.As4()
	remoteID := binary.BigEndian.Uint32(remoteIDbin[:])

	if localID > remoteID {
		return true
	}

	if localID == remoteID && myAS > getASN(open) {
		return true
	}

	return false
}

func (fsm *fsm) bgpMessageResetStats() {
	atomic.StoreUint64(&fsm.counterStats.Received.Total, 0)
	atomic.StoreUint64(&fsm.counterStats.Received.Update, 0)
	atomic.StoreUint64(&fsm.counterStats.Received.Notification, 0)
	atomic.StoreUint64(&fsm.counterStats.Received.Open, 0)
	atomic.StoreUint64(&fsm.counterStats.Received.Refresh, 0)
	atomic.StoreUint64(&fsm.counterStats.Received.Keepalive, 0)
	atomic.StoreUint32(&fsm.counterStats.Received.WithdrawUpdate, 0)
	atomic.StoreUint32(&fsm.counterStats.Received.WithdrawPrefix, 0)
	atomic.StoreUint64(&fsm.counterStats.Received.Discarded, 0)
	atomic.StoreUint64(&fsm.counterStats.Sent.Total, 0)
	atomic.StoreUint64(&fsm.counterStats.Sent.Update, 0)
	atomic.StoreUint64(&fsm.counterStats.Sent.Notification, 0)
	atomic.StoreUint64(&fsm.counterStats.Sent.Open, 0)
	atomic.StoreUint64(&fsm.counterStats.Sent.Refresh, 0)
	atomic.StoreUint64(&fsm.counterStats.Sent.Keepalive, 0)
	atomic.StoreUint32(&fsm.counterStats.Sent.WithdrawUpdate, 0)
	atomic.StoreUint32(&fsm.counterStats.Sent.WithdrawPrefix, 0)
	atomic.StoreUint64(&fsm.counterStats.Sent.Discarded, 0)
	// Reset timer stats
	atomic.StoreInt64(&fsm.timerStats.State.UpdateRecvTime, 0)
}

func (fsm *fsm) bgpMessageStateUpdate(MessageType uint8, isIn bool) {
	if isIn {
		atomic.AddUint64(&fsm.counterStats.Received.Total, 1)
	} else {
		atomic.AddUint64(&fsm.counterStats.Sent.Total, 1)
	}
	switch MessageType {
	case bgp.BGP_MSG_OPEN:
		if isIn {
			atomic.AddUint64(&fsm.counterStats.Received.Open, 1)
		} else {
			atomic.AddUint64(&fsm.counterStats.Sent.Open, 1)
		}
	case bgp.BGP_MSG_UPDATE:
		if isIn {
			atomic.AddUint64(&fsm.counterStats.Received.Update, 1)
			atomic.StoreInt64(&fsm.timerStats.State.UpdateRecvTime, time.Now().Unix())
		} else {
			atomic.AddUint64(&fsm.counterStats.Sent.Update, 1)
		}
	case bgp.BGP_MSG_NOTIFICATION:
		if isIn {
			atomic.AddUint64(&fsm.counterStats.Received.Notification, 1)
		} else {
			atomic.AddUint64(&fsm.counterStats.Sent.Notification, 1)
		}
	case bgp.BGP_MSG_KEEPALIVE:
		if isIn {
			atomic.AddUint64(&fsm.counterStats.Received.Keepalive, 1)
		} else {
			atomic.AddUint64(&fsm.counterStats.Sent.Keepalive, 1)
		}
	case bgp.BGP_MSG_ROUTE_REFRESH:
		if isIn {
			atomic.AddUint64(&fsm.counterStats.Received.Refresh, 1)
		} else {
			atomic.AddUint64(&fsm.counterStats.Sent.Refresh, 1)
		}
	default:
		if isIn {
			atomic.AddUint64(&fsm.counterStats.Received.Discarded, 1)
		} else {
			atomic.AddUint64(&fsm.counterStats.Sent.Discarded, 1)
		}
	}
}

func (fsm *fsm) bmpStatsUpdate(statType uint16, increment int) {
	switch statType {
	// TODO
	// Support other stat types.
	case bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE:
		atomic.AddUint32(&fsm.counterStats.Received.WithdrawUpdate, uint32(increment))
	case bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX:
		atomic.AddUint32(&fsm.counterStats.Received.WithdrawPrefix, uint32(increment))
	}
}

func newFSM(gConf *oc.Global, pConf *oc.Neighbor, state bgp.FSMState, logger *slog.Logger) *fsm {
	pConf.State.SessionState = oc.IntToSessionStateMap[int(state)]
	pConf.Timers.State.Downtime = time.Now().Unix()
	fsm := &fsm{
		gConf:                    gConf,
		outgoingCh:               channels.NewInfiniteChannel(),
		connCh:                   make(chan net.Conn, 1),
		opensentHoldTime:         float64(holdtimeOpensent),
		adminStateCh:             make(chan adminStateOperation, 1),
		capMap:                   make(map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface),
		gracefulRestartTimer:     time.NewTimer(time.Hour),
		notification:             make(chan *bgp.BGPMessage, 1),
		deconfiguredNotification: make(chan *bgp.BGPMessage, 1),
		outgoingConnCh:           make(chan outgoingConn, 1),
		logger:                   logger,
	}
	fsm.pConf.Update(pConf)
	fsm.familyMap.Store(make(map[bgp.Family]bgp.BGPAddPathMode))
	fsm.state.Store(state)
	adminState := adminStateUp
	if pConf.Config.AdminDown {
		adminState = adminStateDown
	}
	fsm.adminState.Store(adminState)
	fsm.gracefulRestartTimer.Stop()
	return fsm
}

func getASN(m *bgp.BGPOpen) uint32 {
	asn := uint32(m.MyAS)
	for _, p := range m.OptParams {
		paramCap, y := p.(*bgp.OptionParameterCapability)
		if !y {
			continue
		}
		for _, c := range paramCap.Capability {
			if c.Code() == bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER {
				cap := c.(*bgp.CapFourOctetASNumber)
				asn = cap.CapValue
			}
		}
	}
	return asn
}

func (fsm *fsm) stateChange(nextState bgp.FSMState, reason *fsmStateReason) {
	fsm.lock.Lock()
	conf := fsm.pConf.ReadCopy()
	defer func() {
		fsm.pConf.Update(&conf)
		fsm.lock.Unlock()
	}()

	fsm.logger.Debug("state changed",
		slog.String("old", fsm.state.String()),
		slog.String("new", nextState.String()),
		slog.String("reason", reason.String()))

	switch nextState {
	case bgp.BGP_FSM_ESTABLISHED:
		remoteTCP := fsm.conn.RemoteAddr().(*net.TCPAddr)
		remoteAddr, _ := netip.AddrFromSlice(remoteTCP.IP)
		remoteAddr = remoteAddr.WithZone(remoteTCP.Zone)

		localTCP := fsm.conn.LocalAddr().(*net.TCPAddr)
		localAddr, _ := netip.AddrFromSlice(localTCP.IP)
		localAddr = localAddr.WithZone(localTCP.Zone)

		conf.Transport.State.RemoteAddress = remoteAddr
		conf.Transport.State.RemotePort = uint16(remoteTCP.Port)
		conf.Transport.State.LocalAddress = localAddr
		conf.Transport.State.LocalPort = uint16(localTCP.Port)

		conf.Timers.State.Uptime = time.Now().Unix()
		conf.State.EstablishedCount++

		body := fsm.recvOpen.Body.(*bgp.BGPOpen)
		localAS := conf.Config.LocalAs
		remoteAS := getASN(body)

		// ASN negotiation was skipped
		asnNegotiationSkipped := conf.Config.PeerAs == 0
		if asnNegotiationSkipped {
			typ := oc.PEER_TYPE_EXTERNAL
			if localAS == remoteAS {
				typ = oc.PEER_TYPE_INTERNAL
			}
			conf.State.PeerType = typ

			fsm.logger.Info("skipped asn negotiation",
				slog.String("State", fsm.state.String()),
				slog.Uint64("Asn", uint64(remoteAS)),
				slog.Any("PeerType", typ))
		} else {
			conf.State.PeerType = conf.Config.PeerType
		}

		conf.State.PeerAs = remoteAS
		conf.State.RemoteRouterId = body.ID
		capmap, rfmap := open2Cap(body, &conf)

		fsm.capMap = capmap
		fsm.familyMap.Store(rfmap)

		// calculate HoldTime
		// RFC 4271 P.13
		// a BGP speaker MUST calculate the value of the Hold Timer
		// by using the smaller of its configured Hold Time and the Hold Time
		// received in the OPEN message.
		holdTime := float64(body.HoldTime)
		myHoldTime := conf.Timers.Config.HoldTime
		if holdTime > myHoldTime {
			conf.Timers.State.NegotiatedHoldTime = myHoldTime
		} else {
			conf.Timers.State.NegotiatedHoldTime = holdTime
		}

		keepalive := conf.Timers.Config.KeepaliveInterval
		if n := conf.Timers.State.NegotiatedHoldTime; n < myHoldTime {
			keepalive = n / 3
		}
		conf.Timers.State.KeepaliveInterval = keepalive

		gr, ok := fsm.capMap[bgp.BGP_CAP_GRACEFUL_RESTART]
		if conf.GracefulRestart.Config.Enabled && ok {
			state := &conf.GracefulRestart.State
			state.Enabled = true
			cap := gr[len(gr)-1].(*bgp.CapGracefulRestart)
			state.PeerRestartTime = cap.Time

			for _, t := range cap.Tuples {
				n := bgp.AddressFamilyNameMap[bgp.NewFamily(t.AFI, t.SAFI)]
				for i, a := range conf.AfiSafis {
					if string(a.Config.AfiSafiName) == n {
						conf.AfiSafis[i].MpGracefulRestart.State.Enabled = true
						conf.AfiSafis[i].MpGracefulRestart.State.Received = true
						break
					}
				}
			}

			// RFC 4724 4.1
			// To re-establish the session with its peer, the Restarting Speaker
			// MUST set the "Restart State" bit in the Graceful Restart Capability
			// of the OPEN message.
			if conf.GracefulRestart.State.PeerRestarting && cap.Flags&0x08 == 0 {
				fsm.logger.Warn("restart flag is not set", slog.String("State", fsm.state.String()))
				// just ignore
			}

			// RFC 4724 3
			// The most significant bit is defined as the Restart State (R)
			// bit, ...(snip)... When set (value 1), this bit
			// indicates that the BGP speaker has restarted, and its peer MUST
			// NOT wait for the End-of-RIB marker from the speaker before
			// advertising routing information to the speaker.
			if conf.GracefulRestart.State.LocalRestarting && cap.Flags&0x08 != 0 {
				fsm.logger.Debug("peer has restarted, skipping wait for EOR", slog.String("State", fsm.state.String()))
				for i := range conf.AfiSafis {
					conf.AfiSafis[i].MpGracefulRestart.State.EndOfRibReceived = true
				}
			}
			if conf.GracefulRestart.Config.NotificationEnabled && cap.Flags&0x04 > 0 {
				conf.GracefulRestart.State.NotificationEnabled = true
			}
		}
		llgr, ok2 := fsm.capMap[bgp.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART]
		if conf.GracefulRestart.Config.LongLivedEnabled && ok && ok2 {
			conf.GracefulRestart.State.LongLivedEnabled = true
			cap := llgr[len(llgr)-1].(*bgp.CapLongLivedGracefulRestart)
			for _, t := range cap.Tuples {
				n := bgp.AddressFamilyNameMap[bgp.NewFamily(t.AFI, t.SAFI)]
				for i, a := range conf.AfiSafis {
					if string(a.Config.AfiSafiName) == n {
						conf.AfiSafis[i].LongLivedGracefulRestart.State.Enabled = true
						conf.AfiSafis[i].LongLivedGracefulRestart.State.Received = true
						conf.AfiSafis[i].LongLivedGracefulRestart.State.PeerRestartTime = t.RestartTime
						break
					}
				}
			}
		}

		fsm.isEBGP = conf.IsEBGPPeer(fsm.gConf)
		fsm.isConfed = conf.IsConfederationMember(fsm.gConf)
		fsm.isTreatAsWithdraw = conf.ErrorHandling.Config.TreatAsWithdraw
		// reset the state set by the previous session
		fsm.twoByteAsTrans = false
		if _, y := fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]; !y {
			fsm.twoByteAsTrans = true
			break
		}
		y := func() bool {
			for _, c := range capabilitiesFromConfig(&conf) {
				switch c.(type) {
				case *bgp.CapFourOctetASNumber:
					return true
				}
			}
			return false
		}()
		if !y {
			fsm.twoByteAsTrans = true
		}
	default:
		conf.Timers.State.Downtime = time.Now().Unix()
	}
}

func (fsm *fsm) sendNotification(conn net.Conn, msg *bgp.BGPMessage) error {
	body := msg.Body.(*bgp.BGPNotification)
	if body.ErrorCode == bgp.BGP_ERROR_CEASE && (body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN || body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET) {
		communication, rest := decodeAdministrativeCommunication(body.Data)
		fsm.logger.Warn("sent notification",
			slog.String("State", fsm.state.String()),
			slog.Int("Code", int(body.ErrorCode)),
			slog.Int("Subcode", int(body.ErrorSubcode)),
			slog.String("Communicated-Reason", communication),
			slog.Any("Data", rest))

		if body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET {
			fsm.lock.Lock()
			conf := fsm.pConf.ReadOnly()
			fsm.idleHoldTime = conf.Timers.Config.IdleHoldTimeAfterReset
			fsm.lock.Unlock()
		}
	} else {
		fsm.logger.Warn("sent notification",
			slog.String("State", fsm.state.String()),
			slog.Int("Code", int(body.ErrorCode)),
			slog.Int("Subcode", int(body.ErrorSubcode)),
			slog.Any("Data", body.Data))
	}
	b, _ := msg.Serialize()
	conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err := conn.Write(b)
	if err == nil {
		fsm.bgpMessageStateUpdate(bgp.BGP_MSG_NOTIFICATION, false)
	}
	conn.Close()
	return err
}

func (fsm *fsm) start(wg *sync.WaitGroup, callback func(*fsmMsg)) {
	ctx, cancel := context.WithCancel(context.Background())
	fsm.h = &fsmHandler{
		fsm:       fsm,
		outgoing:  fsm.outgoingCh,
		ctx:       ctx,
		ctxCancel: cancel,
		callback:  callback,
	}
	wg.Add(1)
	go fsm.h.loop(ctx, wg)
}

func (fsm *fsm) stop() {
	fsm.h.ctxCancel()
}

type fsmCallback func(*fsmMsg)

type fsmHandler struct {
	fsm           *fsm
	allowLoopback bool
	outgoing      *channels.InfiniteChannel
	ctx           context.Context
	ctxCancel     context.CancelFunc
	callback      fsmCallback
}

func (h *fsmHandler) idle(ctx context.Context) (bgp.FSMState, *fsmStateReason) {
	fsm := h.fsm

	idleHoldTimer := time.NewTimer(time.Second * time.Duration(fsm.idleHoldTime))

	for {
		select {
		case <-ctx.Done():
			return -1, newfsmStateReason(fsmDying, nil, nil)
		case <-fsm.gracefulRestartTimer.C:
			conf := fsm.pConf.ReadOnly()
			restarting := conf.GracefulRestart.State.PeerRestarting

			if restarting {
				fsm.logger.Warn("graceful restart timer expired", slog.String("State", fsm.state.String()))
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmRestartTimerExpired, nil, nil)
			}
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			conn.Close()
			fsm.logger.Warn("Closed an accepted connection", slog.String("State", fsm.state.String()))
		case <-idleHoldTimer.C:
			if fsm.adminState.Load() == adminStateUp {
				fsm.logger.Debug("IdleHoldTimer expired", slog.String("State", fsm.state.String()), slog.Int("Duration", int(fsm.idleHoldTime)))
				fsm.idleHoldTime = holdtimeIdle
				return bgp.BGP_FSM_ACTIVE, newfsmStateReason(fsmIdleTimerExpired, nil, nil)
			} else {
				fsm.logger.Debug("IdleHoldTimer expired, but stay at idle because the admin state is DOWN", slog.String("State", fsm.state.String()))
			}

		case stateOp := <-fsm.adminStateCh:
			err := h.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case adminStateDown:
					// stop idle hold timer
					idleHoldTimer.Stop()

				case adminStateUp:
					// restart idle hold timer
					idleHoldTimer.Reset(time.Second * time.Duration(fsm.idleHoldTime))
				}
			}
		}
	}
}

func (h *fsmHandler) connectLoop(ctx context.Context) net.Conn {
	fsm := h.fsm

	retryInterval, addr, port, password, ttl, ttlMin, mss, localAddress, localPort, bindInterface, tos := func() (int, string, int, string, uint8, uint8, uint16, string, int, string, uint8) {
		conf := fsm.pConf.ReadOnly()
		tick := max(int(conf.Timers.Config.ConnectRetry), minConnectRetryInterval)

		addr := conf.State.NeighborAddress
		port := int(bgp.BGP_PORT)
		if conf.Transport.Config.RemotePort != 0 {
			port = int(conf.Transport.Config.RemotePort)
		}
		password := conf.Config.AuthPassword
		ttl := uint8(0)
		ttlMin := uint8(0)
		tos := uint8(0)

		if conf.Transport.Config.IpTos != 0 {
			tos = conf.Transport.Config.IpTos
		}
		if conf.TtlSecurity.Config.Enabled {
			ttl = 255
			ttlMin = conf.TtlSecurity.Config.TtlMin
		} else if conf.Config.PeerAs != 0 && conf.Config.PeerType == oc.PEER_TYPE_EXTERNAL {
			ttl = 1
			if conf.EbgpMultihop.Config.Enabled {
				ttl = conf.EbgpMultihop.Config.MultihopTtl
			}
		}
		return tick, addr.String(), port, password, ttl, ttlMin, conf.Transport.Config.TcpMss, conf.Transport.Config.LocalAddress.String(), int(conf.Transport.Config.LocalPort), conf.Transport.Config.BindInterface, tos
	}()

	tick := minConnectRetryInterval
	for {
		timer := time.NewTimer(time.Duration((0.75+rand.Float64()*0.25)*float64(tick)*1000) * time.Millisecond)
		select {
		case <-ctx.Done():
			fsm.logger.Debug("stop connect loop")
			timer.Stop()
			return nil
		case <-timer.C:
			fsm.logger.Debug("try to connect")
		}

		laddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(localAddress, strconv.Itoa(localPort)))
		if err != nil {
			fsm.logger.Warn("failed to resolve local address")
		}

		if err == nil {
			d := net.Dialer{
				LocalAddr: laddr,
				Timeout:   time.Duration(max(retryInterval-1, minConnectRetryInterval)) * time.Second,
				KeepAlive: -1,
				Control: func(network, address string, c syscall.RawConn) error {
					return netutils.DialerControl(fsm.logger, network, address, c, ttl, ttlMin, mss, password, bindInterface, tos)
				},
			}

			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
			select {
			case <-ctx.Done():
				fsm.logger.Debug("stop connect loop")
				if conn != nil {
					conn.Close()
				}
				return nil
			default:
			}

			if err == nil {
				return conn
			} else {
				fsm.logger.Debug("failed to connect", slog.String("Error", err.Error()))
			}
		}
		tick = retryInterval
	}
}

func (h *fsmHandler) active(ctx context.Context) (bgp.FSMState, *fsmStateReason) {
	fsm := h.fsm

	if fsm.outgoingConnMgr == nil || fsm.outgoingConnMgr.ctx.Err() != nil {
		fsm.logger.Info("starting outgoing connection manager")
		fsm.outgoingConnMgr = newOutGoingConnManager(ctx, fsm)
	}

	for {
		select {
		case <-ctx.Done():
			return -1, newfsmStateReason(fsmDying, nil, nil)
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}

			fsm.lock.Lock()
			fsm.conn = conn
			initializeConn(fsm, conn)
			// we don't implement delayed open timer so move to opensent right
			// away.
			conf := fsm.pConf.ReadCopy()
			m := buildopen(fsm.gConf, &conf)
			fsm.pConf.Update(&conf)
			fsm.lock.Unlock()

			b, _ := m.Serialize()
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			_, err := conn.Write(b)
			if err == nil {
				fsm.bgpMessageStateUpdate(m.Header.Type, false)
				return bgp.BGP_FSM_OPENSENT, newfsmStateReason(fsmNewConnection, nil, nil)
			}
			return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmWriteFailed, nil, []byte(err.Error()))
		case result := <-fsm.outgoingConnCh:
			b, _ := bgp.NewBGPKeepAliveMessage().Serialize()
			result.conn.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := result.conn.Write(b); err != nil {
				result.conn.Close()
				fsm.logger.Warn("failed to send keepalive on outgoing connection", slog.String("Error", err.Error()))
				// the manager was stopped, restart it
				fsm.outgoingConnMgr = newOutGoingConnManager(ctx, fsm)
			} else {
				fsm.bgpMessageStateUpdate(bgp.BGP_MSG_KEEPALIVE, false)
				fsm.lock.Lock()
				fsm.conn = result.conn
				fsm.recvOpen = result.open
				fsm.lock.Unlock()

				return bgp.BGP_FSM_OPENCONFIRM, newfsmStateReason(fsmOpenMsgReceived, result.open, nil)
			}
		case <-fsm.gracefulRestartTimer.C:
			conf := fsm.pConf.ReadOnly()
			restarting := conf.GracefulRestart.State.PeerRestarting
			if restarting {
				fsm.logger.Warn("graceful restart timer expired", slog.String("State", fsm.state.String()))
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmRestartTimerExpired, nil, nil)
			}
		case stateOp := <-fsm.adminStateCh:
			err := h.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case adminStateDown:
					return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmAdminDown, nil, nil)
				case adminStateUp:
					fsm.logger.Error("code logic bug",
						slog.String("State", fsm.state.String()),
						slog.String("AdminState", stateOp.State.String()))
				}
			}
		}
	}
}

func setPeerConnTTL(fsm *fsm, conn net.Conn) error {
	ttl := 0
	ttlMin := 0

	conf := fsm.pConf.ReadOnly()
	if conf.TtlSecurity.Config.Enabled {
		ttl = 255
		ttlMin = int(conf.TtlSecurity.Config.TtlMin)
	} else if conf.Config.PeerAs != 0 && conf.Config.PeerType == oc.PEER_TYPE_EXTERNAL {
		if conf.EbgpMultihop.Config.Enabled {
			ttl = int(conf.EbgpMultihop.Config.MultihopTtl)
		} else {
			ttl = 1
		}
	}

	if ttl != 0 {
		if err := netutils.SetTCPTTLSockopt(conn, ttl); err != nil {
			return fmt.Errorf("failed to set TTL %d: %w", ttl, err)
		}
	}
	if ttlMin != 0 {
		if err := netutils.SetTCPMinTTLSockopt(conn, ttlMin); err != nil {
			return fmt.Errorf("failed to set minimal TTL %d: %w", ttlMin, err)
		}
	}
	return nil
}

func setPeerConnTOS(fsm *fsm, conn net.Conn) error {
	conf := fsm.pConf.ReadOnly()
	tos := conf.Transport.Config.IpTos
	if tos == 0 {
		return nil
	}
	if err := netutils.SetIPTOSSockopt(conn, tos); err != nil {
		return fmt.Errorf("failed to set TOS %d: %w", tos, err)
	}
	return nil
}

func setPeerConnMSS(fsm *fsm, conn net.Conn) error {
	conf := fsm.pConf.ReadOnly()
	mss := conf.Transport.Config.TcpMss
	if mss == 0 {
		return nil
	}
	if err := netutils.SetTCPMSSSockopt(conn, mss); err != nil {
		return fmt.Errorf("failed to set MSS %d: %w", mss, err)
	}
	return nil
}

func capAddPathFromConfig(pConf *oc.Neighbor) bgp.ParameterCapabilityInterface {
	tuples := make([]*bgp.CapAddPathTuple, 0, len(pConf.AfiSafis))
	for _, af := range pConf.AfiSafis {
		var mode bgp.BGPAddPathMode
		if af.AddPaths.State.Receive {
			mode |= bgp.BGP_ADD_PATH_RECEIVE
		}
		if af.AddPaths.State.SendMax > 0 {
			mode |= bgp.BGP_ADD_PATH_SEND
		}
		if mode > 0 {
			tuples = append(tuples, bgp.NewCapAddPathTuple(af.State.Family, mode))
		}
	}
	if len(tuples) == 0 {
		return nil
	}
	return bgp.NewCapAddPath(tuples)
}

func capabilitiesFromConfig(pConf *oc.Neighbor) []bgp.ParameterCapabilityInterface {
	fqdn, _ := os.Hostname()
	caps := make([]bgp.ParameterCapabilityInterface, 0, 4)
	caps = append(caps, bgp.NewCapRouteRefresh())
	caps = append(caps, bgp.NewCapFQDN(fqdn, ""))

	if pConf.Config.SendSoftwareVersion || pConf.Config.PeerType == oc.PEER_TYPE_INTERNAL {
		softwareVersion := fmt.Sprintf("GoBGP/%s", version.Version())
		caps = append(caps, bgp.NewCapSoftwareVersion(softwareVersion))
	}

	for _, af := range pConf.AfiSafis {
		caps = append(caps, bgp.NewCapMultiProtocol(af.State.Family))
	}
	caps = append(caps, bgp.NewCapFourOctetASNumber(pConf.Config.LocalAs))

	if c := pConf.GracefulRestart.Config; c.Enabled {
		tuples := []*bgp.CapGracefulRestartTuple{}
		ltuples := []*bgp.CapLongLivedGracefulRestartTuple{}

		// RFC 4724 4.1
		// To re-establish the session with its peer, the Restarting Speaker
		// MUST set the "Restart State" bit in the Graceful Restart Capability
		// of the OPEN message.
		restarting := pConf.GracefulRestart.State.LocalRestarting

		if !c.HelperOnly {
			for i, rf := range pConf.AfiSafis {
				// Update advertised flag on sending new OPEN message. Retain advertised flag on PeerDown
				// event since remote peer might treat it as Graceful Restart and in this case, GR caps
				// are still "advertised" to it. However, if config is changed to disabled, reset it.
				if m := rf.MpGracefulRestart.Config; m.Enabled {
					// When restarting, always flag forwaring bit.
					// This can be a lie, depending on how gobgpd is used.
					// For a route-server use-case, since a route-server
					// itself doesn't forward packets, and the dataplane
					// is a l2 switch which continues to work with no
					// relation to bgpd, this behavior is ok.
					// TODO consideration of other use-cases
					tuples = append(tuples, bgp.NewCapGracefulRestartTuple(rf.State.Family, restarting))
				}
				pConf.AfiSafis[i].MpGracefulRestart.State.Advertised = rf.MpGracefulRestart.Config.Enabled

				if m := rf.LongLivedGracefulRestart.Config; m.Enabled {
					ltuples = append(ltuples, bgp.NewCapLongLivedGracefulRestartTuple(rf.State.Family, restarting, m.RestartTime))
				}
				pConf.AfiSafis[i].LongLivedGracefulRestart.State.Advertised = rf.LongLivedGracefulRestart.Config.Enabled
			}
		}
		restartTime := c.RestartTime
		notification := c.NotificationEnabled
		caps = append(caps, bgp.NewCapGracefulRestart(restarting, notification, restartTime, tuples))
		if c.LongLivedEnabled {
			caps = append(caps, bgp.NewCapLongLivedGracefulRestart(ltuples))
		}
	}

	// Extended Nexthop Capability (Code 5)
	tuples := []*bgp.CapExtendedNexthopTuple{}
	families, _ := oc.AfiSafis(pConf.AfiSafis).ToRfList()
	for _, family := range families {
		if family == bgp.RF_IPv6_UC {
			continue
		}
		tuple := bgp.NewCapExtendedNexthopTuple(family, bgp.AFI_IP6)
		tuples = append(tuples, tuple)
	}
	if len(tuples) != 0 {
		caps = append(caps, bgp.NewCapExtendedNexthop(tuples))
	}

	// ADD-PATH Capability
	if c := capAddPathFromConfig(pConf); c != nil {
		caps = append(caps, capAddPathFromConfig(pConf))
	}

	return caps
}

// needs to be called with fsm.lock held and fsm.pConf.Store() called after
func buildopen(gConf *oc.Global, pConf *oc.Neighbor) *bgp.BGPMessage {
	caps := capabilitiesFromConfig(pConf)
	opt := bgp.NewOptionParameterCapability(caps)
	holdTime := uint16(pConf.Timers.Config.HoldTime)
	as := pConf.Config.LocalAs
	if as > 1<<16-1 {
		as = bgp.AS_TRANS
	}
	msg, _ := bgp.NewBGPOpenMessage(uint16(as), holdTime, gConf.Config.RouterId,
		[]bgp.OptionParameterInterface{opt})
	return msg
}

func readAll(conn net.Conn, length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func getPathAttrFromBGPUpdate(m *bgp.BGPUpdate, typ bgp.BGPAttrType) bgp.PathAttributeInterface {
	for _, a := range m.PathAttributes {
		if a.GetType() == typ {
			return a
		}
	}
	return nil
}

func hasOwnASLoop(ownAS uint32, limit int, asPath *bgp.PathAttributeAsPath, confedID uint32, confedEnabled bool) bool {
	cnt := 0
	for _, param := range asPath.Value {
		for _, as := range param.GetAS() {
			// RFC 4271: Check own AS number
			if as == ownAS {
				cnt++
				if cnt > limit {
					return true
				}
			}
			// RFC 5065 Section 4: Check Confederation ID
			// "A BGP speaker receiving an AS_PATH attribute containing an
			//  autonomous system matching its own AS Confederation Identifier
			//  SHALL treat the path in the same fashion as if it had received
			//  a path containing its own AS number."
			if confedEnabled && as == confedID && confedID != ownAS {
				cnt++
				if cnt > limit {
					return true
				}
			}
		}
	}
	return false
}

func (h *fsmHandler) handlingError(m *bgp.BGPMessage, e error, useRevisedError bool) bgp.ErrorHandling {
	// ineffectual assignment to handling (ineffassign)
	var handling bgp.ErrorHandling
	if m.Header.Type == bgp.BGP_MSG_UPDATE && useRevisedError {
		factor := e.(*bgp.MessageError)
		handling = factor.ErrorHandling
		switch handling {
		case bgp.ERROR_HANDLING_ATTRIBUTE_DISCARD:
			h.fsm.logger.Warn("Some attributes were discarded",
				slog.String("State", h.fsm.state.String()),
				slog.String("Error", e.Error()))
		case bgp.ERROR_HANDLING_TREAT_AS_WITHDRAW:
			h.fsm.logger.Warn("the received Update message was treated as withdraw",
				slog.String("State", h.fsm.state.String()),
				slog.String("Error", e.Error()))
		case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
			handling = bgp.ERROR_HANDLING_SESSION_RESET
		}
	} else {
		handling = bgp.ERROR_HANDLING_SESSION_RESET
	}
	return handling
}

func (h *fsmHandler) recvMessageWithError(conn net.Conn, stateReasonCh chan<- fsmStateReason) (*fsmMsg, error) {
	headerBuf, err := readAll(conn, bgp.BGP_HEADER_LENGTH)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		// we set a read deadline when we cancel the FSM handler context,
		// so this is expected when the FSM is shutting down.
		// We dont' send a state reason here because the FSM is already
		// shutting down.
		return nil, nil
	} else if err != nil {
		nonblockSendChannel(stateReasonCh, *newfsmStateReason(fsmReadFailed, nil, nil))
		return nil, err
	}

	hd := &bgp.BGPHeader{}
	err = hd.DecodeFromBytes(headerBuf)
	// TODO: RFC 8654
	if err == nil && hd.Len > bgp.BGP_MAX_MESSAGE_LENGTH {
		err = bgp.NewMessageError(bgp.BGP_ERROR_MESSAGE_HEADER_ERROR, bgp.BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "too large BGP message length")
	}
	if err != nil {
		h.fsm.bgpMessageStateUpdate(0, true)
		h.fsm.logger.Warn("Session will be reset due to malformed BGP Header",
			slog.String("State", h.fsm.state.String()),
			slog.String("Error", err.Error()),
		)
		fmsg := &fsmMsg{
			MsgType: fsmMsgBGPMessage,
			MsgData: err,
		}
		return fmsg, err
	}

	bodyBuf, err := readAll(conn, int(hd.Len)-bgp.BGP_HEADER_LENGTH)
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return nil, nil
	} else if err != nil {
		nonblockSendChannel(stateReasonCh, *newfsmStateReason(fsmReadFailed, nil, nil))
		return nil, err
	}

	now := time.Now()
	handling := bgp.ERROR_HANDLING_NONE

	useRevisedError := h.fsm.isTreatAsWithdraw

	m, err := bgp.ParseBGPBody(hd, bodyBuf, &bgp.MarshallingOption{
		AddPath:    h.fsm.familyMap.Load().(map[bgp.Family]bgp.BGPAddPathMode),
		Use2ByteAS: h.fsm.twoByteAsTrans, // true if peer does NOT support 4-byte AS
	})
	if err != nil {
		if m == nil {
			handling = bgp.ERROR_HANDLING_SESSION_RESET
		} else {
			handling = h.handlingError(m, err, useRevisedError)
		}
		h.fsm.bgpMessageStateUpdate(0, true)
	} else {
		h.fsm.bgpMessageStateUpdate(m.Header.Type, true)
	}
	fmsg := &fsmMsg{
		MsgType:   fsmMsgBGPMessage,
		handling:  handling,
		timestamp: now,
		payload:   append(headerBuf, bodyBuf...),
	}

	switch handling {
	case bgp.ERROR_HANDLING_AFISAFI_DISABLE:
		panic("logic bug; AFI/SAFI disable handling should have been converted to session reset")
	case bgp.ERROR_HANDLING_SESSION_RESET:
		h.fsm.logger.Warn("Session will be reset due to malformed BGP message",
			slog.String("State", h.fsm.state.String()),
			slog.String("Error", err.Error()))
		fmsg.MsgData = err
		return fmsg, err
	default:
		fmsg.MsgData = m
	}
	return fmsg, nil
}

func (h *fsmHandler) recvMessage(ctx context.Context, conn net.Conn, recvChan chan<- *fsmMsg, stateReasonCh chan<- fsmStateReason, wg *sync.WaitGroup) {
	defer wg.Done()

	fmsg, _ := h.recvMessageWithError(conn, stateReasonCh)
	if fmsg != nil && ctx.Err() == nil {
		recvChan <- fmsg
	}
}

// needs to be called with fsm.lock held
func open2Cap(open *bgp.BGPOpen, n *oc.Neighbor) (map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface, map[bgp.Family]bgp.BGPAddPathMode) {
	capMap := make(map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface)
	for _, p := range open.OptParams {
		if paramCap, y := p.(*bgp.OptionParameterCapability); y {
			for _, c := range paramCap.Capability {
				m, ok := capMap[c.Code()]
				if !ok {
					m = make([]bgp.ParameterCapabilityInterface, 0, 1)
				}
				capMap[c.Code()] = append(m, c)
			}
		}
	}

	// squash add path cap
	if caps, y := capMap[bgp.BGP_CAP_ADD_PATH]; y {
		items := make([]*bgp.CapAddPathTuple, 0, len(caps))
		for _, c := range caps {
			items = append(items, c.(*bgp.CapAddPath).Tuples...)
		}
		capMap[bgp.BGP_CAP_ADD_PATH] = []bgp.ParameterCapabilityInterface{bgp.NewCapAddPath(items)}
	}

	// remote open message may not include multi-protocol capability
	if _, y := capMap[bgp.BGP_CAP_MULTIPROTOCOL]; !y {
		capMap[bgp.BGP_CAP_MULTIPROTOCOL] = []bgp.ParameterCapabilityInterface{bgp.NewCapMultiProtocol(bgp.RF_IPv4_UC)}
	}

	local := n.CreateRfMap()
	remote := make(map[bgp.Family]bgp.BGPAddPathMode)
	for _, c := range capMap[bgp.BGP_CAP_MULTIPROTOCOL] {
		family := c.(*bgp.CapMultiProtocol).CapValue
		remote[family] = bgp.BGP_ADD_PATH_NONE
		for _, a := range capMap[bgp.BGP_CAP_ADD_PATH] {
			for _, i := range a.(*bgp.CapAddPath).Tuples {
				if i.Family == family {
					remote[family] = i.Mode
				}
			}
		}
	}
	negotiated := make(map[bgp.Family]bgp.BGPAddPathMode)
	for family, mode := range local {
		if m, y := remote[family]; y {
			n := bgp.BGP_ADD_PATH_NONE
			if mode&bgp.BGP_ADD_PATH_SEND > 0 && m&bgp.BGP_ADD_PATH_RECEIVE > 0 {
				n |= bgp.BGP_ADD_PATH_SEND
			}
			if mode&bgp.BGP_ADD_PATH_RECEIVE > 0 && m&bgp.BGP_ADD_PATH_SEND > 0 {
				n |= bgp.BGP_ADD_PATH_RECEIVE
			}
			negotiated[family] = n
		}
	}
	return capMap, negotiated
}

func (fsm *fsm) handleOpen(fmsg *fsmMsg) (bgp.FSMState, *fsmStateReason, *bgp.BGPMessage) {
	switch m := fmsg.MsgData.(type) {
	case *bgp.BGPMessage:
		if m.Header.Type == bgp.BGP_MSG_OPEN {
			body := m.Body.(*bgp.BGPOpen)

			localID := fsm.gConf.Config.RouterId
			conf := fsm.pConf.ReadOnly()
			fsmPeerAS := conf.Config.PeerAs
			localAS := conf.Config.LocalAs

			if _, err := bgp.ValidateOpenMsg(body, fsmPeerAS, localAS, localID); err != nil {
				err := err.(*bgp.MessageError)
				notif := bgp.NewBGPNotificationMessage(err.TypeCode, err.SubTypeCode, err.Data)
				if err.TypeCode == bgp.BGP_ERROR_OPEN_MESSAGE_ERROR && err.SubTypeCode == bgp.BGP_ERROR_SUB_BAD_PEER_AS {
					return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmBadPeerAS, m, nil), notif
				}
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, m, nil), notif
			}
			return bgp.BGP_FSM_OPENCONFIRM, newfsmStateReason(fsmOpenMsgReceived, nil, nil), nil
		}
		return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, m, nil), bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_FSM_ERROR, 1, nil)
	case *bgp.MessageError:
		return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, nil, nil), bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data)
	}
	panic("handleOpen was called with invalid fsmMsg")
}

func (h *fsmHandler) opensent(ctx context.Context) (bgp.FSMState, *fsmStateReason) {
	fsm := h.fsm

	wg := &sync.WaitGroup{}
	wg.Add(1)
	reasonCh := make(chan fsmStateReason, 1)
	recvChan := make(chan *fsmMsg, 1)
	go h.recvMessage(ctx, fsm.conn, recvChan, reasonCh, wg)

	defer func() {
		// for to stop the recv goroutine
		fsm.conn.SetReadDeadline(time.Now())
		wg.Wait()
		close(recvChan)
		// reset the read deadline
		fsm.conn.SetReadDeadline(time.Time{})
	}()

	// RFC 4271 P.60
	// sets its HoldTimer to a large value
	// A HoldTimer value of 4 minutes is suggested as a "large value"
	// for the HoldTimer
	holdTimer := time.NewTimer(time.Second * time.Duration(fsm.opensentHoldTime))

	for {
		select {
		case <-ctx.Done():
			fsm.conn.Close()
			return -1, newfsmStateReason(fsmDying, nil, nil)
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			conn.Close()
			fsm.logger.Warn("Closed an accepted connection", slog.String("State", fsm.state.String()))
		case <-fsm.gracefulRestartTimer.C:
			conf := fsm.pConf.ReadOnly()
			restarting := conf.GracefulRestart.State.PeerRestarting
			if restarting {
				fsm.logger.Warn("graceful restart timer expired", slog.String("State", fsm.state.String()))
				fsm.conn.Close()
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmRestartTimerExpired, nil, nil)
			}
		case e := <-recvChan:
			nextState, reason, notif := fsm.handleOpen(e)
			if nextState != bgp.BGP_FSM_OPENCONFIRM {
				if notif != nil {
					_ = fsm.sendNotification(fsm.conn, notif)
				} else {
					fsm.conn.Close()
				}
				return nextState, reason
			}
			m := e.MsgData.(*bgp.BGPMessage)

			fsm.lock.Lock()
			fsm.recvOpen = m
			fsm.lock.Unlock()

			if outConn, ok := fsm.tryReceiveOutgoingConn(); ok {
				// collision detected
				isDominant := fsm.isDominant(m.Body.(*bgp.BGPOpen))
				if isDominant {
					// close the incoming connection
					fsm.logger.Debug("collision detected: dominant on active side, close the incoming connection")
					fsm.conn.Close()
					fsm.conn = outConn.conn
					fsm.lock.Lock()
					fsm.recvOpen = outConn.open
					fsm.lock.Unlock()
				} else {
					// close the outgoing connection
					fsm.logger.Debug("collision detected: dominant on passive side, close the outgoing connection")
					outConn.conn.Close()
				}
			}

			b, _ := bgp.NewBGPKeepAliveMessage().Serialize()
			fsm.conn.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := fsm.conn.Write(b); err != nil {
				fsm.conn.Close()
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmWriteFailed, nil, nil)
			}
			// stop to try to connect.
			if fsm.outgoingConnMgr.state.Load() == bgp.BGP_FSM_CONNECT {
				fsm.outgoingConnMgr.stop()
			}

			fsm.bgpMessageStateUpdate(bgp.BGP_MSG_KEEPALIVE, false)
			return bgp.BGP_FSM_OPENCONFIRM, newfsmStateReason(fsmOpenMsgReceived, nil, nil)
		case result := <-fsm.outgoingConnCh:
			incomingConn := fsm.conn
			fsm.conn = result.conn
			fsm.lock.Lock()
			fsm.recvOpen = result.open
			fsm.lock.Unlock()

			var e *fsmMsg
			select {
			case e = <-recvChan:
			default:
			}
			if e != nil {
				nextState, _, _ := fsm.handleOpen(e)
				if nextState == bgp.BGP_FSM_OPENCONFIRM {
					// collision detected
					isDominant := fsm.isDominant(result.open.Body.(*bgp.BGPOpen))
					if isDominant {
						// close the incoming connection
						fsm.logger.Debug("collision detected: dominant on active side, close the incoming connection")
						incomingConn.Close()
					} else {
						// close the outgoing connection
						fsm.logger.Debug("collision detected: dominant on passive side, close the outgoing connection")
						result.conn.Close()
						fsm.conn = incomingConn
						fsm.lock.Lock()
						fsm.recvOpen = e.MsgData.(*bgp.BGPMessage)
						fsm.lock.Unlock()
					}
				}
			}
			b, _ := bgp.NewBGPKeepAliveMessage().Serialize()
			fsm.conn.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := fsm.conn.Write(b); err != nil {
				fsm.conn.Close()
				fsm.logger.Warn("failed to send keepalive on outgoing connection", slog.String("Error", err.Error()))
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmWriteFailed, nil, nil)
			}
			fsm.bgpMessageStateUpdate(bgp.BGP_MSG_KEEPALIVE, false)
			return bgp.BGP_FSM_OPENCONFIRM, newfsmStateReason(fsmOpenMsgReceived, result.open, nil)
		case err := <-reasonCh:
			fsm.conn.Close()
			return bgp.BGP_FSM_IDLE, &err
		case <-holdTimer.C:
			m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil)
			_ = fsm.sendNotification(fsm.conn, m)
			return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmHoldTimerExpired, m, nil)
		case stateOp := <-fsm.adminStateCh:
			err := h.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case adminStateDown:
					fsm.conn.Close()
					return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmAdminDown, nil, nil)
				case adminStateUp:
					h.fsm.logger.Error("code logic bug",
						slog.String("State", fsm.state.String()),
						slog.String("AdminState", stateOp.State.String()))
				}
			}
		}
	}
}

func keepaliveTicker(fsm *fsm) *time.Ticker {
	fsm.lock.Lock()
	defer fsm.lock.Unlock()

	conf := fsm.pConf.ReadOnly()
	negotiatedTime := conf.Timers.State.NegotiatedHoldTime
	if negotiatedTime == 0 {
		return &time.Ticker{}
	}
	sec := time.Second * time.Duration(conf.Timers.State.KeepaliveInterval)
	if sec == 0 {
		sec = time.Second
	}
	return time.NewTicker(sec)
}

func (h *fsmHandler) openconfirm(ctx context.Context) (bgp.FSMState, *fsmStateReason) {
	fsm := h.fsm
	ticker := keepaliveTicker(fsm)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	reasonCh := make(chan fsmStateReason, 1)
	recvChan := make(chan *fsmMsg, 1)
	go h.recvMessage(ctx, fsm.conn, recvChan, reasonCh, wg)

	defer func() {
		// for to stop the recv goroutine
		fsm.conn.SetReadDeadline(time.Now())
		wg.Wait()
		close(recvChan)
		// reset the read deadline
		fsm.conn.SetReadDeadline(time.Time{})
	}()

	fsm.lock.Lock()
	var holdTimer *time.Timer
	conf := fsm.pConf.ReadCopy()
	if conf.Timers.State.NegotiatedHoldTime == 0 {
		holdTimer = &time.Timer{}
	} else {
		// RFC 4271 P.65
		// sets the HoldTimer according to the negotiated value
		holdTimer = time.NewTimer(time.Second * time.Duration(conf.Timers.State.NegotiatedHoldTime))
	}
	fsm.pConf.Update(&conf)
	fsm.lock.Unlock()

	for {
		select {
		case <-ctx.Done():
			fsm.conn.Close()
			return -1, newfsmStateReason(fsmDying, nil, nil)
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			conn.Close()
			fsm.logger.Warn("Closed an accepted connection", slog.String("State", fsm.state.String()))
		case <-fsm.gracefulRestartTimer.C:
			conf := fsm.pConf.ReadOnly()
			restarting := conf.GracefulRestart.State.PeerRestarting
			if restarting {
				fsm.logger.Warn("graceful restart timer expired", slog.String("State", fsm.state.String()))
				fsm.conn.Close()
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmRestartTimerExpired, nil, nil)
			}
		case <-ticker.C:
			m := bgp.NewBGPKeepAliveMessage()
			b, _ := m.Serialize()
			fsm.conn.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := fsm.conn.Write(b); err != nil {
				fsm.conn.Close()
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmWriteFailed, nil, nil)
			}
			fsm.bgpMessageStateUpdate(m.Header.Type, false)
		case e := <-recvChan:
			switch m := e.MsgData.(type) {
			case *bgp.BGPMessage:
				if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
					return bgp.BGP_FSM_ESTABLISHED, newfsmStateReason(fsmOpenMsgNegotiated, nil, nil)
				}
				// send notification ?
				fsm.conn.Close()
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, nil, nil)
			case *bgp.MessageError:
				n := bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data)
				_ = fsm.sendNotification(fsm.conn, n)
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, n, nil)
			default:
				fsm.logger.Error("unknown msg type",
					slog.String("State", fsm.state.String()),
					slog.Any("Data", e.MsgData))
			}
		case err := <-reasonCh:
			fsm.conn.Close()
			return bgp.BGP_FSM_IDLE, &err
		case <-holdTimer.C:
			m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil)
			_ = fsm.sendNotification(fsm.conn, m)
			return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmHoldTimerExpired, m, nil)
		case stateOp := <-fsm.adminStateCh:
			err := h.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case adminStateDown:
					fsm.conn.Close()
					return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmAdminDown, nil, nil)
				case adminStateUp:
					fsm.logger.Error("code logic bug",
						slog.String("State", fsm.state.String()),
						slog.String("adminState", stateOp.State.String()))
				}
			}
		}
	}
}

func (h *fsmHandler) sendMessageloop(ctx context.Context, conn net.Conn, stateReasonCh chan<- fsmStateReason, wg *sync.WaitGroup) error {
	defer wg.Done()
	fsm := h.fsm
	ticker := keepaliveTicker(fsm)
	send := func(m *bgp.BGPMessage) error {
		if fsm.twoByteAsTrans && m.Header.Type == bgp.BGP_MSG_UPDATE {
			fsm.logger.Debug("update for 2byte AS peer",
				slog.String("State", fsm.state.String()),
				slog.Any("Data", m))
			table.UpdatePathAttrs2ByteAs(m.Body.(*bgp.BGPUpdate))
			table.UpdatePathAggregator2ByteAs(m.Body.(*bgp.BGPUpdate))
		}

		b, err := m.Serialize(&bgp.MarshallingOption{AddPath: fsm.familyMap.Load().(map[bgp.Family]bgp.BGPAddPathMode)})
		if err != nil {
			fsm.logger.Warn("failed to serialize",
				slog.String("State", fsm.state.String()),
				slog.String("Error", err.Error()))
			fsm.bgpMessageStateUpdate(0, false)
			return nil
		}
		_, err = conn.Write(b)
		if err != nil {
			fsm.logger.Warn("failed to send",
				slog.String("State", fsm.state.String()),
				slog.Any("Data", err))

			nonblockSendChannel(stateReasonCh, *newfsmStateReason(fsmWriteFailed, nil, nil))
			conn.Close()
			return fmt.Errorf("closed")
		}
		fsm.bgpMessageStateUpdate(m.Header.Type, false)

		switch m.Header.Type {
		case bgp.BGP_MSG_UPDATE:
			update := m.Body.(*bgp.BGPUpdate)
			fsm.logger.Debug("sent update",
				slog.String("State", fsm.state.String()),
				slog.Any("nlri", update.NLRI),
				slog.Any("withdrawals", update.WithdrawnRoutes),
				slog.Any("attributes", update.PathAttributes))
		case bgp.BGP_MSG_KEEPALIVE:
			// nothing to do
		default:
			fsm.logger.Error("unexpected message sent",
				slog.String("State", fsm.state.String()),
				slog.Int("Type", int(m.Header.Type)),
				slog.Any("data", m))
		}
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case o := <-h.outgoing.Out():
			switch m := o.(type) {
			case *fsmOutgoingMsg:
				const maxCoalesceMsgs = 2048 // safety cap
				paths := m.Paths
				coalescedMsgs := 1
				// coalesce queued messages for more efficient UPDATE packing
				for coalescedMsgs < maxCoalesceMsgs {
					select {
					case <-ctx.Done():
						return nil
					default:
					}
					select {
					case o2 := <-h.outgoing.Out():
						if m2, ok := o2.(*fsmOutgoingMsg); ok {
							paths = append(paths, m2.Paths...)
							coalescedMsgs++
							continue
						}
						return nil
					default:
					}
					// yield for InfiniteChannel's pump goroutine
					if h.outgoing.Len() > 0 {
						runtime.Gosched()
						continue
					}
					break
				}

				options := &bgp.MarshallingOption{AddPath: fsm.familyMap.Load().(map[bgp.Family]bgp.BGPAddPathMode)}
				for _, msg := range table.CreateUpdateMsgFromPaths(paths, options) {
					if err := send(msg); err != nil {
						return nil
					}
				}
			default:
				return nil
			}
		case <-ticker.C:
			if err := send(bgp.NewBGPKeepAliveMessage()); err != nil {
				return nil
			}
		}
	}
}

func (h *fsmHandler) recvMessageloop(ctx context.Context, conn net.Conn, holdtimerResetCh chan<- struct{}, stateReasonCh chan<- fsmStateReason, wg *sync.WaitGroup) {
	defer wg.Done()

	for ctx.Err() == nil {
		fmsg, err := h.recvMessageWithError(conn, stateReasonCh)
		if fmsg != nil && ctx.Err() == nil {
			if m, ok := fmsg.MsgData.(*bgp.MessageError); ok {
				nonblockSendChannel(h.fsm.notification, bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data))
				// finish the loop
				return
			} else {
				doCallback := true
				m := fmsg.MsgData.(*bgp.BGPMessage)
				switch m.Header.Type {
				case bgp.BGP_MSG_ROUTE_REFRESH:
					// nothing to do here
				case bgp.BGP_MSG_UPDATE:
					// if the length of holdtimerResetCh
					// isn't zero, the timer will be reset
					// soon anyway.
					nonblockSendChannel(holdtimerResetCh, struct{}{})
					body := m.Body.(*bgp.BGPUpdate)

					rfMap := h.fsm.familyMap.Load().(map[bgp.Family]bgp.BGPAddPathMode)
					handling := fmsg.handling
					useRevisedError := h.fsm.isTreatAsWithdraw

					var validationErr error
					if handling == bgp.ERROR_HANDLING_NONE {
						ok, ve := bgp.ValidateUpdateMsg(body, rfMap, h.fsm.isEBGP, h.fsm.isConfed, h.allowLoopback)
						if !ok {
							validationErr = ve
							handling = h.handlingError(m, ve, useRevisedError)
							fmsg.handling = handling
						}
					}
					if handling == bgp.ERROR_HANDLING_SESSION_RESET {
						h.fsm.logger.Warn("Session will be reset due to malformed BGP update message",
							slog.String("State", h.fsm.state.String()),
							slog.String("Error", validationErr.Error()))
						fmsg.MsgData = validationErr
						m := validationErr.(*bgp.MessageError)
						nonblockSendChannel(h.fsm.notification, bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data))
						return
					}

					if routes := len(body.WithdrawnRoutes); routes > 0 {
						h.fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
						h.fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
					} else if attr := getPathAttrFromBGPUpdate(body, bgp.BGP_ATTR_TYPE_MP_UNREACH_NLRI); attr != nil {
						mpUnreach := attr.(*bgp.PathAttributeMpUnreachNLRI)
						if routes = len(mpUnreach.Value); routes > 0 {
							h.fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, 1)
							h.fsm.bmpStatsUpdate(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, routes)
						}
					}

					table.UpdatePathAttrs4ByteAs(h.fsm.logger, body)

					if err = table.UpdatePathAggregator4ByteAs(body); err != nil {
						m := err.(*bgp.MessageError)
						nonblockSendChannel(h.fsm.notification, bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data))
						return
					}
					fallthrough
				case bgp.BGP_MSG_KEEPALIVE:
					// if the length of holdtimerResetCh
					// isn't zero, the timer will be reset
					// soon anyway.
					nonblockSendChannel(holdtimerResetCh, struct{}{})
					if m.Header.Type == bgp.BGP_MSG_KEEPALIVE {
						doCallback = false
					}
				case bgp.BGP_MSG_NOTIFICATION:
					doCallback = false
					body := m.Body.(*bgp.BGPNotification)
					if body.ErrorCode == bgp.BGP_ERROR_CEASE && (body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN || body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET) {
						communication, rest := decodeAdministrativeCommunication(body.Data)
						h.fsm.logger.Warn("received notification",
							slog.Int("Code", int(body.ErrorCode)),
							slog.Int("Subcode", int(body.ErrorSubcode)),
							slog.String("Communicated-Reason", communication),
							slog.Any("Data", rest),
						)
					} else {
						h.fsm.logger.Warn("received notification",
							slog.Int("Code", int(body.ErrorCode)),
							slog.Int("Subcode", int(body.ErrorSubcode)),
							slog.Any("Data", body.Data))
					}

					conf := h.fsm.pConf.ReadOnly()
					s := conf.GracefulRestart.State
					hardReset := s.Enabled && s.NotificationEnabled && body.ErrorCode == bgp.BGP_ERROR_CEASE && body.ErrorSubcode == bgp.BGP_ERROR_SUB_HARD_RESET
					if hardReset {
						nonblockSendChannel(stateReasonCh, *newfsmStateReason(fsmHardReset, m, nil))
					} else {
						nonblockSendChannel(stateReasonCh, *newfsmStateReason(fsmNotificationRecv, m, nil))
					}
				}

				if doCallback {
					h.callback(fmsg)
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (h *fsmHandler) established(ctx context.Context) (bgp.FSMState, *fsmStateReason) {
	fsm := h.fsm

	// reset the write deadline that was set in the connection establishment.
	fsm.conn.SetWriteDeadline(time.Time{})

	ioCtx, cancel := context.WithCancel(ctx)
	wg := &sync.WaitGroup{}
	wg.Add(2)

	// send and recv goroutine send errors to reasonCh, and the loop goroutine also sends
	// to reasonCh with hold timer expiration. So three buffer is enough.
	reasonCh := make(chan fsmStateReason, 3)

	holdtimerResetCh := make(chan struct{}, 2)

	go h.sendMessageloop(ioCtx, fsm.conn, reasonCh, wg)
	go h.recvMessageloop(ioCtx, fsm.conn, holdtimerResetCh, reasonCh, wg)

	defer func() {
		// for to stop the recv goroutine
		fsm.conn.SetReadDeadline(time.Now())
		cancel()
		wg.Wait()
	}()

	fsm.lock.Lock()
	var holdTimer *time.Timer
	conf := fsm.pConf.ReadCopy()
	if conf.Timers.State.NegotiatedHoldTime == 0 {
		holdTimer = &time.Timer{}
	} else {
		holdTimer = time.NewTimer(time.Second * time.Duration(conf.Timers.State.NegotiatedHoldTime))
	}
	fsm.pConf.Update(&conf)
	fsm.lock.Unlock()

	fsm.gracefulRestartTimer.Stop()

	convertNotification := func(m *bgp.BGPMessage) *bgp.BGPMessage {
		// RFC8538 defines a Hard Reset notification subcode which
		// indicates that the BGP speaker wants to reset the session
		// without triggering graceful restart procedures. Here we map
		// notification subcodes to the Hard Reset subcode following
		// the RFC8538 suggestion.
		//
		// We check Status instead of Config because RFC8538 states
		// that A BGP speaker SHOULD NOT send a Hard Reset to a peer
		// from which it has not received the "N" bit.
		if conf.GracefulRestart.State.NotificationEnabled {
			if m.Body.(*bgp.BGPNotification).ErrorCode == bgp.BGP_ERROR_CEASE && bgp.ShouldHardReset(m.Body.(*bgp.BGPNotification).ErrorSubcode, false) {
				return bgp.NewBGPNotificationMessage(m.Body.(*bgp.BGPNotification).ErrorCode, bgp.BGP_ERROR_SUB_HARD_RESET, m.Body.(*bgp.BGPNotification).Data)
			}
		}
		return m
	}

	for {
		select {
		case <-ctx.Done():
			var m *bgp.BGPMessage
			select {
			case m = <-fsm.deconfiguredNotification:
				m = convertNotification(m)
				_ = fsm.sendNotification(fsm.conn, m)
			default:
				// fsm.sendNotification closes the connection.
				fsm.conn.Close()
			}
			return -1, newfsmStateReason(fsmDeConfigured, m, nil)
		case m := <-fsm.notification:
			m = convertNotification(m)
			_ = fsm.sendNotification(fsm.conn, m)
			return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmNotificationSent, m, nil)
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			conn.Close()
			fsm.logger.Warn("Closed an accepted connection", slog.String("State", fsm.state.String()))
		case err := <-reasonCh:
			fsm.conn.Close()
			// if recv goroutine hit an error and sent to
			// stateReasonCh, then tx goroutine might take
			// long until it exits because it waits for
			// ctx.Done() or keepalive timer. So let kill
			// it now.
			h.outgoing.In() <- err
			conf := fsm.pConf.ReadOnly()
			if s := conf.GracefulRestart.State; s.Enabled {
				if s.NotificationEnabled && err.Type == fsmNotificationRecv ||
					err.Type == fsmNotificationSent &&
						err.BGPNotification.Body.(*bgp.BGPNotification).ErrorCode == bgp.BGP_ERROR_HOLD_TIMER_EXPIRED ||
					err.Type == fsmReadFailed ||
					err.Type == fsmWriteFailed {
					err = *newfsmStateReason(fsmGracefulRestart, nil, nil)
					fsm.logger.Info("peer graceful restart", slog.String("State", fsm.state.String()))
					fsm.lock.Lock()
					fsm.gracefulRestartTimer.Reset(time.Duration(conf.GracefulRestart.State.PeerRestartTime) * time.Second)
					fsm.lock.Unlock()
				}
			}
			return bgp.BGP_FSM_IDLE, &err
		case <-holdTimer.C:
			fsm.logger.Warn("hold timer expired", slog.String("State", fsm.state.String()))

			m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil)
			err := fsm.sendNotification(fsm.conn, m)

			conf := fsm.pConf.ReadOnly()
			s := conf.GracefulRestart.State
			// Do not return hold timer expired to server if graceful restart is enabled
			// Let it fallback to read/write error or fsmNotificationSent handled above
			// Reference: https://github.com/osrg/gobgp/issues/2174
			if !s.Enabled {
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmHoldTimerExpired, m, nil)
			} else if err != nil {
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmWriteFailed, nil, nil)
			}
			reasonCh <- *newfsmStateReason(fsmNotificationSent, m, nil)
		case <-holdtimerResetCh:
			conf := fsm.pConf.ReadOnly()
			if conf.Timers.State.NegotiatedHoldTime != 0 {
				holdTimer.Reset(time.Second * time.Duration(conf.Timers.State.NegotiatedHoldTime))
			}
		case stateOp := <-fsm.adminStateCh:
			err := h.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case adminStateDown:
					m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, stateOp.Communication)
					_ = fsm.sendNotification(fsm.conn, m)
					return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmAdminDown, m, nil)
				case adminStatePfxCt:
					_ = fsm.sendNotification(fsm.conn, bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED, nil))
				}
			}
		}
	}
}

func (h *fsmHandler) loop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()

	fsm := h.fsm
	oldState := fsm.state.Load()

	var reason *fsmStateReason
	nextState := bgp.FSMState(-1)

	for ctx.Err() == nil {
		switch oldState {
		case bgp.BGP_FSM_IDLE:
			nextState, reason = h.idle(ctx)
			// case bgp.BGP_FSM_CONNECT:
			// 	nextState = h.connect()
		case bgp.BGP_FSM_ACTIVE:
			nextState, reason = h.active(ctx)
		case bgp.BGP_FSM_OPENSENT:
			nextState, reason = h.opensent(ctx)
		case bgp.BGP_FSM_OPENCONFIRM:
			nextState, reason = h.openconfirm(ctx)
		case bgp.BGP_FSM_ESTABLISHED:
			// Allow updates from host loopback addresses if the BGP connection
			// with the neighbour is both dialed and received on loopback
			// addresses.
			remoteTCP := fsm.conn.RemoteAddr().(*net.TCPAddr)
			remoteAddr, _ := netip.AddrFromSlice(remoteTCP.IP)
			localTCP := fsm.conn.LocalAddr().(*net.TCPAddr)
			localAddr, _ := netip.AddrFromSlice(localTCP.IP)
			h.allowLoopback = remoteAddr.Is4() && localAddr.Is4() && remoteAddr.IsLoopback() && localAddr.IsLoopback()

			nextState, reason = h.established(ctx)
		}

		if nextState == bgp.BGP_FSM_ESTABLISHED && oldState == bgp.BGP_FSM_OPENCONFIRM {
			fsm.logger.Info("Peer Up")
		}

		if oldState == bgp.BGP_FSM_ESTABLISHED {
			fsm.logger.Info("Peer Down",
				slog.String("State", oldState.String()),
				slog.String("Reason", reason.String()))
		}

		switch reason.Type {
		case fsmAdminDown, fsmGracefulRestart:
			if fsm.outgoingConnMgr != nil {
				fsm.outgoingConnMgr.stop()
			}
		}

		if ctx.Err() != nil {
			break
		}

		h.fsm.stateChange(nextState, reason)

		msg := &fsmMsg{
			MsgType:     fsmMsgStateChange,
			MsgData:     nextState,
			StateReason: reason,
		}

		h.callback(msg)
		fsm.state.Store(nextState)
		oldState = nextState
	}

	select {
	case conn := <-fsm.connCh:
		conn.Close()
	default:
	}
	if fsm.conn != nil {
		fsm.conn.Close()
	}
	close(fsm.connCh)
	cleanInfiniteChannel(fsm.outgoingCh)
}

func (h *fsmHandler) changeadminState(s adminState) error {
	fsm := h.fsm
	old := fsm.adminState.Load()
	if fsm.adminState.CompareAndSwap(old, s) {
		fsm.logger.Debug("admin state changed",
			slog.String("State", fsm.state.String()),
			slog.String("adminState", s.String()))

		h.fsm.lock.Lock()
		conf := fsm.pConf.ReadCopy()
		conf.State.AdminDown = !conf.State.AdminDown
		fsm.pConf.Update(&conf)
		h.fsm.lock.Unlock()

		switch s {
		case adminStateUp:
			fsm.logger.Info("Administrative start", slog.String("State", fsm.state.String()))
		case adminStateDown:
			fsm.logger.Info("Administrative shutdown", slog.String("State", fsm.state.String()))

		case adminStatePfxCt:
			fsm.logger.Info("Administrative shutdown(Prefix limit reached)", slog.String("State", fsm.state.String()))
		}
	} else {
		fsm.logger.Warn("cannot change to the same state", slog.String("State", fsm.state.String()))
		return fmt.Errorf("cannot change to the same state")
	}
	return nil
}
