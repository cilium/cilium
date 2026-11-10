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
	"github.com/osrg/gobgp/v4/internal/pkg/gr"
	"github.com/osrg/gobgp/v4/internal/pkg/netutils"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/internal/pkg/version"
	"github.com/osrg/gobgp/v4/pkg/config/oc"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
)

const (
	minConnectRetryInterval = 2

	// The first connection attempt after the FSM leaves Idle waits a
	// random time in [0, firstConnectDelayMax). In RFC 4271 Section 8.2.2,
	// on a start event in the Idle state, the local system "initiates a
	// TCP connection to the other BGP peer". The RFC does not ask for a
	// wait there, and FRR connects at once. We still wait a little: when
	// a session goes down, both sides leave Idle at about the same time,
	// and connections made at the same time collide. Only the random part
	// of the wait makes the two sides connect at different times.
	firstConnectDelayMax = time.Second
)

// firstConnectDelay returns the wait before the first connection attempt
// after the FSM leaves Idle.
func firstConnectDelay() time.Duration {
	return time.Duration(rand.Float64() * float64(firstConnectDelayMax))
}

// connectRetryDelay returns the wait before the next connection attempt.
// RFC 4271 Section 10 says: "The suggested default amount of jitter SHALL
// be determined by multiplying the base value of the appropriate timer by
// a random factor, which is uniformly distributed in the range from 0.75
// to 1.0."
func connectRetryDelay(interval int) time.Duration {
	return time.Duration((0.75 + rand.Float64()*0.25) * float64(interval) * float64(time.Second))
}

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
	fsmInvalidMsg
	fsmNewConnection
	fsmOpenMsgReceived
	fsmOpenMsgNegotiated
	fsmHardReset
	fsmDeConfigured
	fsmBadPeerAS
	// ResetPeer. BGPNotification is the NOTIFICATION sent to the peer, or
	// nil if the session had no connection to send it on.
	fsmAdminReset
)

type fsmStateReason struct {
	Type            fsmStateReasonType
	BGPNotification *bgp.BGPNotification
	Data            []byte
}

func newfsmStateReason(typ fsmStateReasonType, notif *bgp.BGPNotification, data []byte) *fsmStateReason {
	return &fsmStateReason{
		Type:            typ,
		BGPNotification: notif,
		Data:            data,
	}
}

// notificationBody returns the NOTIFICATION body of m, or nil when m is nil.
// m must be a NOTIFICATION message.
func notificationBody(m *bgp.BGPMessage) *bgp.BGPNotification {
	if m == nil {
		return nil
	}
	return m.Body.(*bgp.BGPNotification)
}

// notificationMessage rebuilds the NOTIFICATION message that the reason
// carries. The result serializes to the same bytes as the message that was
// sent to or received from the peer.
func (r *fsmStateReason) notificationMessage() *bgp.BGPMessage {
	if r.BGPNotification == nil {
		return nil
	}
	n := r.BGPNotification
	return bgp.NewBGPNotificationMessage(n.ErrorCode, n.ErrorSubcode, n.Data)
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
		n := r.BGPNotification
		return fmt.Sprintf("notification-sent %s", bgp.NewNotificationErrorCode(n.ErrorCode, n.ErrorSubcode).String())
	case fsmNotificationRecv:
		n := r.BGPNotification
		return fmt.Sprintf("notification-received %s", bgp.NewNotificationErrorCode(n.ErrorCode, n.ErrorSubcode).String())
	case fsmHoldTimerExpired:
		return "hold-timer-expired"
	case fsmIdleTimerExpired:
		return "idle-hold-timer-expired"
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
	case fsmAdminReset:
		if n := r.BGPNotification; n != nil {
			return fmt.Sprintf("notification-sent %s", bgp.NewNotificationErrorCode(n.ErrorCode, n.ErrorSubcode).String())
		}
		return "admin-reset"
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

	// The idle hold time backs off like the start timer of FRR: it starts
	// at 1 second, doubles each time a session ends with a NOTIFICATION,
	// and goes back to 1 second when a session reaches Established.
	idleHoldTimeInitial = 1
	idleHoldTimeMax     = 120
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

// adminStateChLen is the number of admin state requests that can wait for
// the FSM. The FSM does not read adminStateCh while it changes state, so
// requests sent back to back, such as DisablePeer, EnablePeer and
// DisablePeer, must wait in the channel.
const adminStateChLen = 16

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

func (s *fsmState) CompareAndSwap(old, new bgp.FSMState) bool {
	return s.val.CompareAndSwap(int32(old), int32(new))
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
	// notif closes a connection on which the OPEN was sent, when the
	// manager is stopped. nil means just close it. stop() sets it before
	// it cancels ctx. It is atomic because ctx can also be canceled by its
	// parent.
	notif atomic.Pointer[bgp.BGPMessage]
}

// newOutGoingConnManager starts a manager that connects to the peer after
// delay.
func newOutGoingConnManager(ctx context.Context, fsm *fsm, delay time.Duration) *outgoingConnManager {
	cctx, cancel := context.WithCancel(ctx)
	ocm := &outgoingConnManager{
		ctx:    cctx,
		cancel: cancel,
		fsm:    fsm,
	}
	ocm.state.Store(bgp.BGP_FSM_CONNECT)
	ocm.wg.Add(1)
	go ocm.run(fsm.outgoingConnCh, delay)

	return ocm
}

func (ocm *outgoingConnManager) run(ch chan<- outgoingConn, delay time.Duration) {
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
		case bgp.BGP_FSM_IDLE:
			// opensent() took the manager over to stop it.
			return
		case bgp.BGP_FSM_CONNECT:
			conn = ocm.fsm.h.connectLoop(ocm.ctx, delay)
			// We come back here only when this connection failed, so
			// the next attempt is a retry.
			delay = connectRetryDelay(minConnectRetryInterval)
			if ocm.ctx.Err() != nil {
				// right after connectLoop() returns a connection, the context may be canceled.
				if conn != nil {
					conn.Close()
				}
				return
			}
			// Move to OpenSent before the OPEN goes out. opensent()
			// stops the manager only while it is in Connect, with the
			// same compare-and-swap. So the manager is never stopped
			// after it sent its OPEN: the peer may keep this connection
			// when it resolves a collision.
			if !ocm.state.CompareAndSwap(bgp.BGP_FSM_CONNECT, bgp.BGP_FSM_OPENSENT) {
				conn.Close()
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
				ocm.state.Store(bgp.BGP_FSM_CONNECT)
				continue
			}
			fsm.bgpMessageStateUpdate(bgp.BGP_MSG_OPEN, false)
			fsm.logger.Debug("outgoing connection established")
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
				wg.Wait()
				if notif := ocm.notif.Load(); notif != nil {
					_ = fsm.sendNotification(conn, notif)
				} else {
					conn.Close()
				}
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

// adminResetNotification returns the NOTIFICATION that ResetPeer sends.
func adminResetNotification(communication []byte) *bgp.BGPMessage {
	return bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET, communication)
}

// stopOutgoingConnMgr stops the outgoing connection manager, if any. A
// connection on which it sent its OPEN is closed with notif.
func (fsm *fsm) stopOutgoingConnMgr(notif *bgp.BGPMessage) {
	if fsm.outgoingConnMgr != nil {
		fsm.outgoingConnMgr.stop(notif)
	}
}

// stop stops the manager. A connection on which the OPEN was sent is closed
// with notif, or just closed if notif is nil.
func (ocm *outgoingConnManager) stop(notif *bgp.BGPMessage) {
	ocm.notif.Store(notif)
	ocm.cancel()
	ocm.wg.Wait()
	// drain
	for {
		select {
		case c := <-ocm.fsm.outgoingConnCh:
			if notif != nil {
				_ = ocm.fsm.sendNotification(c.conn, notif)
			} else {
				c.conn.Close()
			}
		default:
			return
		}
	}
}

// keepForIdle is called when the session goes to Idle. It stops the manager,
// unless the manager has a connection on which it sent its OPEN, or one that
// it left in fsm.outgoingConnCh. Returns true if it has such a connection.
func (ocm *outgoingConnManager) keepForIdle() bool {
	ch := ocm.fsm.outgoingConnCh
	if len(ch) > 0 {
		return true
	}
	if ocm.ctx.Err() != nil {
		// The manager has returned. If it returned after it sent a
		// connection, the connection is in the channel now.
		return len(ch) > 0
	}
	// Take the manager over like opensent() does, so that a manager that
	// sent its OPEN is never stopped here.
	if ocm.state.CompareAndSwap(bgp.BGP_FSM_CONNECT, bgp.BGP_FSM_IDLE) {
		ocm.stop(nil)
		return false
	}
	return ocm.state.Load() == bgp.BGP_FSM_OPENSENT
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

// tcpAoKeyBinding is a peer's resolved TCP-AO configuration:
// a reference to a shared keychain plus the peer's preferred send ID.
//
// Keychain's key additions and deletions mutate the shared keychain under its lock,
// socketKeys() can be used to take live key snapshots for socket operations.
type tcpAoKeyBinding struct {
	keychain        *tcpAoKeychain
	preferredSendID uint8
}

func (b *tcpAoKeyBinding) socketKeys() (*tcpAoSocketKeys, error) {
	return b.keychain.socketKeys(b.preferredSendID)
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

	// extendedMessage is the RFC 8654 negotiation result: true iff
	// both sides advertised the Extended Message Capability in OPEN.
	// Read on the incoming-message hot path (read loop length gate),
	// so atomic to keep the read lock-free without copying capMap.
	extendedMessage atomic.Bool

	// safe for concurrent access
	state                    fsmState
	familyMap                atomic.Value // map[bgp.Family]bgp.BGPAddPathMode
	rtcEORWait               atomic.Bool
	logger                   *slog.Logger
	outgoingCh               *channels.InfiniteChannel
	notification             chan *bgp.BGPMessage
	deconfiguredNotification chan *bgp.BGPMessage
	resetCh                  chan []byte // ResetPeer, with the communication
	connCh                   chan net.Conn
	adminState               adminStateRaw
	adminStateCh             chan adminStateOperation
	outgoingConnCh           chan outgoingConn

	// tcpAoKeyBinding holds resolved TCP-AO configuration for the peer:
	// - Passive peers have all configured keys installed on matching listening sockets;
	//   preferred key is not set on the listener until an inbound connection is accepted and matched to the peer.
	// - Active peers install all keys in net.Dialer.Control in connectLoop() and mark the preferred key during installation.
	// - Async keychain update causes update of keys directly on the listening sockets and fsm conn sockets of the affected peers.
	//   This is handled on best effort; keychain update is not rolled back upon individual socket operation errors.
	// - Attaching, removing, or changing a keychain of a peer always uses peer delete-and-add path.
	//   A preferred key change within the same keychain is handled live by updating RNext on the current connection.
	tcpAoKeyBinding atomic.Pointer[tcpAoKeyBinding]

	// only loop goroutine accesses; no lock required
	outgoingConnMgr   *outgoingConnManager
	idleHoldTime      float64 // for the current or next Idle state
	idleHoldBackoff   float64
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

// isDominant compares the BGP Identifiers for connection collision according
// to RFC 4271 Section 6.8 and RFC 6286 Section 2.3.
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

// resolveCollision decides which of the two colliding connections is kept.
// open is the OPEN message from the peer. The connection that is not kept is
// closed with Cease/Connection Collision Resolution. RFC 4271 Section 6.8
// says: "Closing the BGP connection (that results from the collision
// resolution procedure) is accomplished by sending the NOTIFICATION message
// with the Error Code Cease." Returns true if the outgoing connection is kept.
func (fsm *fsm) resolveCollision(open *bgp.BGPOpen, incoming, outgoing net.Conn) bool {
	notif := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION, nil)
	if fsm.isDominant(open) {
		fsm.logger.Debug("collision detected: dominant on active side, close the incoming connection")
		_ = fsm.sendNotification(incoming, notif)
		return true
	}
	fsm.logger.Debug("collision detected: dominant on passive side, close the outgoing connection")
	_ = fsm.sendNotification(outgoing, notif)
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
	pConf.Timers.State.Downtime = 0
	fsm := &fsm{
		gConf:                    gConf,
		outgoingCh:               channels.NewInfiniteChannel(),
		connCh:                   make(chan net.Conn, 1),
		opensentHoldTime:         float64(holdtimeOpensent),
		idleHoldBackoff:          idleHoldTimeInitial,
		adminStateCh:             make(chan adminStateOperation, adminStateChLen),
		capMap:                   make(map[bgp.BGPCapabilityCode][]bgp.ParameterCapabilityInterface),
		notification:             make(chan *bgp.BGPMessage, 1),
		deconfiguredNotification: make(chan *bgp.BGPMessage, 1),
		resetCh:                  make(chan []byte, 1),
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

		// RFC 8654 Section 4: a speaker MAY send a BGP Extended
		// Message only if the peer advertised the BGP Extended
		// Message Capability. We always advertise the capability
		// (the OPEN-side advertisement is unconditional, like the
		// 4-byte ASN capability), so the negotiated flag is simply
		// whether the peer's capability map contains an entry for
		// the Extended Message Capability.
		_, peerExt := fsm.capMap[bgp.BGP_CAP_EXTENDED_MESSAGE]
		fsm.extendedMessage.Store(peerExt)

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

		// The negotiated graceful restart State below comes from the
		// OPEN of this session. Clear the values of the previous
		// session first. Otherwise a peer that no longer advertises
		// graceful restart, or no longer advertises it for a family,
		// is still handled as if it did.
		conf.GracefulRestart.State.Enabled = false
		conf.GracefulRestart.State.PeerRestartTime = 0
		conf.GracefulRestart.State.NotificationEnabled = false
		conf.GracefulRestart.State.LongLivedEnabled = false
		for i := range conf.AfiSafis {
			conf.AfiSafis[i].MpGracefulRestart.State.Enabled = false
			conf.AfiSafis[i].MpGracefulRestart.State.Received = false
			conf.AfiSafis[i].LongLivedGracefulRestart.State.Enabled = false
			conf.AfiSafis[i].LongLivedGracefulRestart.State.Received = false
			conf.AfiSafis[i].LongLivedGracefulRestart.State.PeerRestartTime = 0
		}

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
		fsm.isConfed = fsm.gConf.IsConfederationMember(conf.Config.PeerAs)
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
	}
}

// grNegotiated returns what the current session negotiated, for the graceful
// restart of the peer. The capabilities are set only if they are
// negotiated: we advertised them, and the peer sent them.
func (fsm *fsm) grNegotiated() gr.Negotiated {
	fsm.lock.Lock()
	defer fsm.lock.Unlock()

	n := gr.Negotiated{Families: make(map[bgp.Family]bool)}
	for f := range fsm.familyMap.Load().(map[bgp.Family]bgp.BGPAddPathMode) {
		n.Families[f] = true
	}
	state := fsm.pConf.ReadOnly().GracefulRestart.State
	if caps := fsm.capMap[bgp.BGP_CAP_GRACEFUL_RESTART]; state.Enabled && len(caps) > 0 {
		n.GR = caps[len(caps)-1].(*bgp.CapGracefulRestart)
	}
	if caps := fsm.capMap[bgp.BGP_CAP_LONG_LIVED_GRACEFUL_RESTART]; state.LongLivedEnabled && len(caps) > 0 {
		n.LLGR = caps[len(caps)-1].(*bgp.CapLongLivedGracefulRestart)
	}
	return n
}

func (fsm *fsm) sendNotification(conn net.Conn, msg *bgp.BGPMessage) error {
	body := msg.Body.(*bgp.BGPNotification)
	if body.ErrorCode == bgp.BGP_ERROR_CEASE && (body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN || body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET) {
		communication, rest := decodeAdministrativeCommunication(body.Data)
		fsm.logger.Info("sent notification",
			slog.String("State", fsm.state.String()),
			slog.Int("Code", int(body.ErrorCode)),
			slog.Int("Subcode", int(body.ErrorSubcode)),
			slog.String("Communicated-Reason", communication),
			slog.Any("Data", rest))
	} else {
		fsm.logger.Info("sent notification",
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

// sendEstablishedNotification sends m on the connection of the session in
// Established and returns the message that was sent.
//
// RFC 8538 defines the Hard Reset subcode of Cease. It ends the session
// without the graceful restart procedures. When the "N" bit was exchanged,
// a Cease with a subcode for which bgp.ShouldHardReset() is true is sent as
// a Hard Reset, as RFC 8538 Section 5.1 suggests. The Hard Reset carries
// the original NOTIFICATION in its data. RFC 8538 Section 3.1 says "In
// short, the Hard Reset encapsulates another NOTIFICATION message in its
// data portion."
//
// For Administrative Reset, RFC 8538 Section 5.1 leaves the choice to the
// user ("Provide user control"). It is sent as a Hard Reset: ResetPeer
// ends the session on purpose, and the routes are not kept.
//
// The State, not the Config, is checked because RFC 8538 Section 4 says
// "A BGP speaker SHOULD NOT send a Hard Reset to a peer from which it has
// not received the "N" bit." The State is set when the session enters
// Established, so the other states must not use this function.
func (fsm *fsm) sendEstablishedNotification(m *bgp.BGPMessage) (*bgp.BGPMessage, error) {
	body := m.Body.(*bgp.BGPNotification)
	if fsm.pConf.ReadOnly().GracefulRestart.State.NotificationEnabled &&
		body.ErrorCode == bgp.BGP_ERROR_CEASE && bgp.ShouldHardReset(body.ErrorSubcode, true) {
		data := append([]byte{body.ErrorCode, body.ErrorSubcode}, body.Data...)
		m = bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_HARD_RESET, data)
	}
	return m, fsm.sendNotification(fsm.conn, m)
}

func (fsm *fsm) logRecvNotification(body *bgp.BGPNotification) {
	if body.ErrorCode == bgp.BGP_ERROR_CEASE && (body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN || body.ErrorSubcode == bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET) {
		communication, rest := decodeAdministrativeCommunication(body.Data)
		fsm.logger.Info("received notification",
			slog.String("State", fsm.state.String()),
			slog.Int("Code", int(body.ErrorCode)),
			slog.Int("Subcode", int(body.ErrorSubcode)),
			slog.String("Communicated-Reason", communication),
			slog.Any("Data", rest))
	} else {
		fsm.logger.Info("received notification",
			slog.String("State", fsm.state.String()),
			slog.Int("Code", int(body.ErrorCode)),
			slog.Int("Subcode", int(body.ErrorSubcode)),
			slog.Any("Data", body.Data))
	}
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

// nextIdleHoldTime returns the idle hold time of the Idle state that the
// session enters for reason, and the new backoff value. backoff is the
// current backoff value, and afterReset is idle-hold-time-after-reset.
func nextIdleHoldTime(backoff, afterReset float64, reason *fsmStateReason) (float64, float64) {
	switch reason.Type {
	case fsmAdminDown:
		// The session stays in Idle until the admin state goes up. Then
		// it starts again like a new session.
		return idleHoldTimeInitial, idleHoldTimeInitial
	case fsmAdminReset:
		return afterReset, idleHoldTimeInitial
	case fsmNotificationSent, fsmNotificationRecv, fsmHardReset, fsmHoldTimerExpired, fsmInvalidMsg, fsmBadPeerAS:
		backoff = min(backoff*2, idleHoldTimeMax)
	}
	// The other reasons, for example a closed TCP connection, keep the
	// current value.
	return backoff, backoff
}

func (h *fsmHandler) idle(ctx context.Context) (bgp.FSMState, *fsmStateReason) {
	fsm := h.fsm

	idleHoldTimer := time.NewTimer(time.Second * time.Duration(fsm.idleHoldTime))

	for {
		select {
		case <-ctx.Done():
			return -1, newfsmStateReason(fsmDying, nil, nil)
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			conn.Close()
			fsm.logger.Warn("Closed an accepted connection", slog.String("State", fsm.state.String()))
		case <-idleHoldTimer.C:
			if fsm.adminState.Load() == adminStateUp {
				fsm.logger.Debug("IdleHoldTimer expired", slog.String("State", fsm.state.String()), slog.Int("Duration", int(fsm.idleHoldTime)))
				return bgp.BGP_FSM_ACTIVE, newfsmStateReason(fsmIdleTimerExpired, nil, nil)
			} else {
				fsm.logger.Debug("IdleHoldTimer expired, but stay at idle because the admin state is DOWN", slog.String("State", fsm.state.String()))
			}

		case <-fsm.resetCh:
			// ResetPeer. Like FRR, ignore it while the peer is
			// administratively down.
			if fsm.adminState.Load() == adminStateUp {
				conf := fsm.pConf.ReadOnly()
				fsm.idleHoldTime, fsm.idleHoldBackoff = nextIdleHoldTime(fsm.idleHoldBackoff, conf.Timers.Config.IdleHoldTimeAfterReset, newfsmStateReason(fsmAdminReset, nil, nil))
				idleHoldTimer.Reset(time.Second * time.Duration(fsm.idleHoldTime))
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

// connectLoop connects to the peer after delay, and retries until it
// succeeds or ctx is canceled.
func (h *fsmHandler) connectLoop(ctx context.Context, delay time.Duration) net.Conn {
	fsm := h.fsm

	retryInterval, addr, port, password, ttl, ttlMin, mss, localAddress, localPort, bindInterface, tos := func() (int, netip.Addr, int, string, uint8, uint8, uint16, string, int, string, uint8) {
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
		return tick, addr, port, password, ttl, ttlMin, conf.Transport.Config.TcpMss, conf.Transport.Config.LocalAddress.String(), int(conf.Transport.Config.LocalPort), conf.Transport.Config.BindInterface, tos
	}()

	for {
		timer := time.NewTimer(delay)
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
					var tcpAO *netutils.TCPAOConfig
					if keyBinding := fsm.tcpAoKeyBinding.Load(); keyBinding != nil {
						tcpAoKeys, err := keyBinding.socketKeys()
						if err != nil {
							return fmt.Errorf("failed to load TCP-AO keychain for peer %s: %w", addr, err)
						}
						config, err := tcpAoKeys.netutilsConfig(true)
						if err != nil {
							return fmt.Errorf("failed to configure TCP-AO for peer %s: %w", addr, err)
						}
						tcpAO = &config
					}
					return netutils.DialerControl(fsm.logger, network, address, c, ttl, ttlMin, mss, password, bindInterface, tos, tcpAO)
				},
			}
			conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr.String(), strconv.Itoa(port)))
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
		delay = connectRetryDelay(retryInterval)
	}
}

func (h *fsmHandler) active(ctx context.Context) (bgp.FSMState, *fsmStateReason) {
	fsm := h.fsm

	if fsm.outgoingConnMgr == nil || fsm.outgoingConnMgr.ctx.Err() != nil {
		fsm.logger.Info("starting outgoing connection manager")
		fsm.outgoingConnMgr = newOutGoingConnManager(ctx, fsm, firstConnectDelay())
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
				fsm.outgoingConnMgr = newOutGoingConnManager(ctx, fsm, connectRetryDelay(minConnectRetryInterval))
			} else {
				fsm.bgpMessageStateUpdate(bgp.BGP_MSG_KEEPALIVE, false)
				fsm.lock.Lock()
				fsm.conn = result.conn
				fsm.recvOpen = result.open
				fsm.lock.Unlock()

				// The manager that sent this connection has returned, but
				// this function may have started a new one above, when it
				// found the old one done. The session now uses our own
				// connection, so another outgoing connection is not
				// needed. openconfirm() relies on this: an outgoing
				// connection that it receives always collides with an
				// incoming one.
				fsm.outgoingConnMgr.stop(nil)

				return bgp.BGP_FSM_OPENCONFIRM, newfsmStateReason(fsmOpenMsgReceived, nil, nil)
			}
		case communication := <-fsm.resetCh:
			// ResetPeer. There is no connection to send the
			// NOTIFICATION on, except the one of the manager.
			fsm.stopOutgoingConnMgr(adminResetNotification(communication))
			return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmAdminReset, nil, nil)
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

	// RFC 8654 Section 3: advertise the Extended Message Capability
	// in OPEN unconditionally, mirroring how the 4-byte ASN capability
	// is handled. The TLV is empty (Capability Code 6, Length 0);
	// per Section 4 a side may only emit a message larger than 4096
	// octets after both peers have advertised, so the actual length
	// cap flip still depends on the negotiation result on the FSM.
	caps = append(caps, bgp.NewCapExtendedMessage())

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

	// Extended Nexthop Capability (Code 5). RFC 8950 Section 4:
	//
	//   Since this document only concerns itself with the advertisement of
	//   IPv4 NLRI and VPN-IPv4 NLRI with an IPv6 next hop, this specification
	//   only allows the following values in the Capability Value field of the
	//   Extended Next Hop Encoding capability:
	//
	//   *  NLRI AFI = 1 (IPv4)
	//
	//   *  NLRI SAFI = 1, 2, 4, 128, or 129
	//
	//   *  Nexthop AFI = 2 (IPv6)
	tuples := []*bgp.CapExtendedNexthopTuple{}
	families, _ := oc.AfiSafis(pConf.AfiSafis).ToRfList()
	for _, family := range families {
		switch family {
		case bgp.RF_IPv4_UC, bgp.RF_IPv4_MC, bgp.RF_IPv4_MPLS, bgp.RF_IPv4_VPN, bgp.RF_IPv4_VPN_MC:
			tuples = append(tuples, bgp.NewCapExtendedNexthopTuple(family, bgp.AFI_IP6))
		}
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
	// RFC 8654 Section 4 + Section 6: once both peers have advertised
	// the Extended Message Capability the per-message-type cap rises
	// from 4096 to 65535 octets, but OPEN and KEEPALIVE keep the
	// legacy ceiling so the initial handshake stays interoperable
	// with implementations that have not yet negotiated the
	// capability (the handshake completes before the negotiation
	// result is known).
	if err == nil {
		maxLen := uint16(bgp.BGP_MAX_MESSAGE_LENGTH)
		if h.fsm.extendedMessage.Load() {
			switch hd.Type {
			case bgp.BGP_MSG_UPDATE, bgp.BGP_MSG_NOTIFICATION, bgp.BGP_MSG_ROUTE_REFRESH:
				maxLen = uint16(bgp.BGP_MAX_EXTENDED_MESSAGE_LENGTH)
			}
		}
		if hd.Len > maxLen {
			err = bgp.NewMessageError(bgp.BGP_ERROR_MESSAGE_HEADER_ERROR, bgp.BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, binary.BigEndian.AppendUint16(nil, hd.Len), fmt.Sprintf("too large BGP message length %d", hd.Len))
		}
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
		AddPath:         h.fsm.familyMap.Load().(map[bgp.Family]bgp.BGPAddPathMode),
		Use2ByteAS:      h.fsm.twoByteAsTrans, // true if peer does NOT support 4-byte AS
		ExtendedMessage: h.fsm.extendedMessage.Load(),
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
					return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmBadPeerAS, notificationBody(notif), nil), notif
				}
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, notificationBody(notif), nil), notif
			}
			return bgp.BGP_FSM_OPENCONFIRM, newfsmStateReason(fsmOpenMsgReceived, nil, nil), nil
		}
		// RFC 4271 8.2.2: a NOTIFICATION with a version error (Event 24)
		// in OpenSent gets no answer. The connection is just dropped.
		if m.Header.Type == bgp.BGP_MSG_NOTIFICATION {
			body := m.Body.(*bgp.BGPNotification)
			if body.ErrorCode == bgp.BGP_ERROR_OPEN_MESSAGE_ERROR && body.ErrorSubcode == bgp.BGP_ERROR_SUB_UNSUPPORTED_VERSION_NUMBER {
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmNotificationRecv, body, nil), nil
			}
		}
		notif := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_FSM_ERROR, 1, nil)
		return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, notificationBody(notif), nil), notif
	case *bgp.MessageError:
		notif := bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data)
		return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, notificationBody(notif), nil), notif
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
				if fsm.resolveCollision(m.Body.(*bgp.BGPOpen), fsm.conn, outConn.conn) {
					fsm.conn = outConn.conn
					fsm.lock.Lock()
					fsm.recvOpen = outConn.open
					fsm.lock.Unlock()
				}
			}

			b, _ := bgp.NewBGPKeepAliveMessage().Serialize()
			fsm.conn.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := fsm.conn.Write(b); err != nil {
				fsm.conn.Close()
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmWriteFailed, nil, nil)
			}
			// Stop trying to connect, unless the manager has moved to
			// OpenSent to send its OPEN (see outgoingConnManager.run()).
			if fsm.outgoingConnMgr.state.CompareAndSwap(bgp.BGP_FSM_CONNECT, bgp.BGP_FSM_IDLE) {
				fsm.outgoingConnMgr.stop(nil)
			}

			fsm.bgpMessageStateUpdate(bgp.BGP_MSG_KEEPALIVE, false)
			return bgp.BGP_FSM_OPENCONFIRM, newfsmStateReason(fsmOpenMsgReceived, nil, nil)
		case result := <-fsm.outgoingConnCh:
			// The peer's OPEN arrived on our own connection, while the
			// incoming connection waits for the peer's OPEN. RFC 4271
			// Section 6.8 says: "A BGP speaker MAY also examine
			// connections in an OpenSent state if it knows the BGP
			// Identifier of the peer by means outside of the protocol."
			// Read literally, an OPEN on the other connection is not a
			// means outside of the protocol. We still use it, like FRR
			// does: both connections are with the same peer, so its BGP
			// Identifier is known. Resolve the collision now.
			if !fsm.resolveCollision(result.open.Body.(*bgp.BGPOpen), fsm.conn, result.conn) {
				// The incoming connection is kept. Stay in OpenSent
				// and wait for the peer's OPEN on it.
				continue
			}
			// resolveCollision closed the incoming connection. Its recv
			// goroutine ends with a read error; drop what it reported.
			wg.Wait()
			select {
			case <-recvChan:
			default:
			}
			select {
			case <-reasonCh:
			default:
			}

			fsm.lock.Lock()
			fsm.conn = result.conn
			fsm.recvOpen = result.open
			fsm.lock.Unlock()

			b, _ := bgp.NewBGPKeepAliveMessage().Serialize()
			fsm.conn.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := fsm.conn.Write(b); err != nil {
				fsm.conn.Close()
				fsm.logger.Warn("failed to send keepalive on outgoing connection", slog.String("Error", err.Error()))
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmWriteFailed, nil, nil)
			}
			fsm.bgpMessageStateUpdate(bgp.BGP_MSG_KEEPALIVE, false)
			return bgp.BGP_FSM_OPENCONFIRM, newfsmStateReason(fsmOpenMsgReceived, nil, nil)
		case err := <-reasonCh:
			fsm.conn.Close()
			return bgp.BGP_FSM_IDLE, &err
		case <-holdTimer.C:
			m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil)
			_ = fsm.sendNotification(fsm.conn, m)
			return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmHoldTimerExpired, notificationBody(m), nil)
		case communication := <-fsm.resetCh:
			m := adminResetNotification(communication)
			_ = fsm.sendNotification(fsm.conn, m)
			fsm.stopOutgoingConnMgr(m)
			return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmAdminReset, notificationBody(m), nil)
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

	newHoldTimer := func() *time.Timer {
		conf := fsm.pConf.ReadOnly()
		if conf.Timers.State.NegotiatedHoldTime == 0 {
			return &time.Timer{}
		}
		// RFC 4271 P.65
		// sets the HoldTimer according to the negotiated value
		return time.NewTimer(time.Second * time.Duration(conf.Timers.State.NegotiatedHoldTime))
	}
	holdTimer := newHoldTimer()

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
		case result := <-fsm.outgoingConnCh:
			// The peer's OPEN arrived on our own connection while the
			// incoming connection is in OpenConfirm. RFC 4271 Section 6.8
			// says: "Upon receipt of an OPEN message, the local system
			// MUST examine all of its connections that are in the
			// OpenConfirm state."
			if !fsm.resolveCollision(result.open.Body.(*bgp.BGPOpen), fsm.conn, result.conn) {
				continue
			}
			// resolveCollision closed the incoming connection. Its recv
			// goroutine ends with a read error; drop what it reported.
			wg.Wait()
			select {
			case <-recvChan:
			default:
			}
			select {
			case <-reasonCh:
			default:
			}

			fsm.lock.Lock()
			fsm.conn = result.conn
			fsm.recvOpen = result.open
			fsm.lock.Unlock()

			b, _ := bgp.NewBGPKeepAliveMessage().Serialize()
			fsm.conn.SetWriteDeadline(time.Now().Add(time.Second))
			if _, err := fsm.conn.Write(b); err != nil {
				fsm.conn.Close()
				fsm.logger.Warn("failed to send keepalive on outgoing connection", slog.String("Error", err.Error()))
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmWriteFailed, nil, nil)
			}
			fsm.bgpMessageStateUpdate(bgp.BGP_MSG_KEEPALIVE, false)

			wg.Add(1)
			go h.recvMessage(ctx, fsm.conn, recvChan, reasonCh, wg)
			// The old hold timer is not stopped. Its channel is no longer
			// read, and the timer for hold time zero cannot be stopped.
			holdTimer = newHoldTimer()
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
				switch m.Header.Type {
				case bgp.BGP_MSG_KEEPALIVE:
					return bgp.BGP_FSM_ESTABLISHED, newfsmStateReason(fsmOpenMsgNegotiated, nil, nil)
				case bgp.BGP_MSG_NOTIFICATION:
					// RFC 4271 8.2.2, OpenConfirm state: "If the local
					// system receives a TcpConnectionFails event (Event 18)
					// from the underlying TCP or a NOTIFICATION message
					// (Event 25), the local system: ... - drops the TCP
					// connection, ... - changes its state to Idle." and "If
					// the local system receives a NOTIFICATION message with
					// a version error (NotifMsgVerErr (Event 24)), the local
					// system: ... - drops the TCP connection, and - changes
					// its state to Idle." Neither list has a step that sends
					// a NOTIFICATION.
					body := m.Body.(*bgp.BGPNotification)
					fsm.logRecvNotification(body)
					fsm.conn.Close()
					return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmNotificationRecv, body, nil)
				}
				// send notification ?
				fsm.conn.Close()
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, nil, nil)
			case *bgp.MessageError:
				n := bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data)
				_ = fsm.sendNotification(fsm.conn, n)
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmInvalidMsg, notificationBody(n), nil)
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
			return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmHoldTimerExpired, notificationBody(m), nil)
		case communication := <-fsm.resetCh:
			m := adminResetNotification(communication)
			_ = fsm.sendNotification(fsm.conn, m)
			fsm.stopOutgoingConnMgr(m)
			return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmAdminReset, notificationBody(m), nil)
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

		b, err := m.Serialize(&bgp.MarshallingOption{
			AddPath:         fsm.familyMap.Load().(map[bgp.Family]bgp.BGPAddPathMode),
			ExtendedMessage: fsm.extendedMessage.Load(),
		})
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

				options := &bgp.MarshallingOption{
					AddPath:         fsm.familyMap.Load().(map[bgp.Family]bgp.BGPAddPathMode),
					ExtendedMessage: fsm.extendedMessage.Load(),
				}
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

func (h *fsmHandler) recvMessageloop(ctx context.Context, conn net.Conn, holdtimerResetCh chan<- struct{}, stateReasonCh chan<- fsmStateReason, processing *atomic.Bool, wg *sync.WaitGroup) {
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
					// A discarded attribute leaves the rest of the message in
					// use, so the semantic checks still have to run on what is
					// left. Treat-as-withdraw is not validated: the attribute
					// that failed to decode is still in the message, half
					// decoded, and its NLRI are withdrawn anyway. A repeated
					// MP_REACH_NLRI or MP_UNREACH_NLRI, which must reset the
					// session even then, is caught by the decoder. A session
					// reset never gets here.
					if handling == bgp.ERROR_HANDLING_NONE || handling == bgp.ERROR_HANDLING_ATTRIBUTE_DISCARD {
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

					if !h.fsm.twoByteAsTrans {
						table.DiscardAs4Attrs(body)
					}
					table.UpdatePathAggregator4ByteAs(body)
					table.UpdatePathAttrs4ByteAs(h.fsm.logger, body)
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
					h.fsm.logRecvNotification(body)

					if body.ErrorCode == bgp.BGP_ERROR_CEASE && body.ErrorSubcode == bgp.BGP_ERROR_SUB_HARD_RESET {
						nonblockSendChannel(stateReasonCh, *newfsmStateReason(fsmHardReset, body, nil))
					} else {
						nonblockSendChannel(stateReasonCh, *newfsmStateReason(fsmNotificationRecv, body, nil))
					}
				}

				if doCallback {
					processing.Store(true)
					h.callback(fmsg)
					processing.Store(false)
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

	// send and recv goroutine send errors to reasonCh. So two buffers are enough.
	reasonCh := make(chan fsmStateReason, 2)

	holdtimerResetCh := make(chan struct{}, 2)

	// processing is true while the recv goroutine waits for the server to
	// process a message. See the holdTimer case.
	var processing atomic.Bool

	go h.sendMessageloop(ioCtx, fsm.conn, reasonCh, wg)
	go h.recvMessageloop(ioCtx, fsm.conn, holdtimerResetCh, reasonCh, &processing, wg)

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

	for {
		select {
		case <-ctx.Done():
			var m *bgp.BGPMessage
			select {
			case m = <-fsm.deconfiguredNotification:
				m, _ = fsm.sendEstablishedNotification(m)
			default:
				// fsm.sendNotification closes the connection.
				fsm.conn.Close()
			}
			return -1, newfsmStateReason(fsmDeConfigured, notificationBody(m), nil)
		case m := <-fsm.notification:
			m, _ = fsm.sendEstablishedNotification(m)
			return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmNotificationSent, notificationBody(m), nil)
		case conn, ok := <-fsm.connCh:
			if !ok {
				break
			}
			n := fsm.grNegotiated()
			if !n.HasFamilies() {
				conn.Close()
				fsm.logger.Warn("Closed an accepted connection", slog.String("State", fsm.state.String()))
				break
			}
			// RFC 4724 Section 4.2: "In case it does not detect the
			// termination of the old TCP session and still considers
			// the BGP session as being established, it MUST treat the
			// subsequent open connection from the peer as an indication
			// of the termination of the old TCP session and act
			// accordingly (when the Graceful Restart Capability has
			// been received from the peer)." and "Since the previous
			// connection is considered to be terminated, no
			// NOTIFICATION message should be sent -- the previous TCP
			// session is simply closed."
			//
			// Section 5 changes the Established state: "if the Graceful
			// Restart Capability with one or more AFIs/SAFIs has been
			// received for the session, then in response to Event 16 or
			// Event 17 the local system: ... changes its state to
			// Connect." Active also does the work of Connect here.
			//
			// A peer may list no AFI/SAFI in the Graceful Restart
			// Capability and use long-lived graceful restart only. RFC
			// 9494 Section 4.1 says the Graceful Restart Capability is
			// required "to enable the reuse of certain base mechanisms
			// that are common to both "flavors" notably: origination,
			// collection, and processing of EoR as well as the
			// finite-state-machine modifications and connection-reset
			// logic introduced by GR." We read this as: the families in
			// the Long-Lived Graceful Restart Capability count too.
			fsm.conn.Close()
			// active() takes the connection. idle() would close it.
			select {
			case fsm.connCh <- conn:
			default:
				// Another connection from the peer is queued. active()
				// takes that one.
				conn.Close()
			}
			return bgp.BGP_FSM_ACTIVE, newfsmStateReason(fsmNewConnection, nil, nil)
		case err := <-reasonCh:
			fsm.conn.Close()
			// if recv goroutine hit an error and sent to
			// stateReasonCh, then tx goroutine might take
			// long until it exits because it waits for
			// ctx.Done() or keepalive timer. So let kill
			// it now.
			h.outgoing.In() <- err
			return bgp.BGP_FSM_IDLE, &err
		case <-holdTimer.C:
			if processing.Load() {
				// The recv goroutine read a message from the peer and
				// reset the hold timer, and now waits for the server to
				// process it, for example during a long API call. It
				// reads the next messages, the KEEPALIVE messages too,
				// only after that. The delay is ours, not the peer's,
				// so the session is not ended.
				fsm.logger.Debug("hold timer expired while a message is processed",
					slog.String("State", fsm.state.String()))
				conf := fsm.pConf.ReadOnly()
				holdTimer.Reset(time.Second * time.Duration(conf.Timers.State.NegotiatedHoldTime))
				break
			}
			fsm.logger.Warn("hold timer expired", slog.String("State", fsm.state.String()))

			m, err := fsm.sendEstablishedNotification(bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_HOLD_TIMER_EXPIRED, 0, nil))
			if err != nil {
				return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmWriteFailed, nil, nil)
			}
			return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmHoldTimerExpired, notificationBody(m), nil)
		case <-holdtimerResetCh:
			conf := fsm.pConf.ReadOnly()
			if conf.Timers.State.NegotiatedHoldTime != 0 {
				holdTimer.Reset(time.Second * time.Duration(conf.Timers.State.NegotiatedHoldTime))
			}
		case communication := <-fsm.resetCh:
			m, _ := fsm.sendEstablishedNotification(adminResetNotification(communication))
			return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmAdminReset, notificationBody(m), nil)
		case stateOp := <-fsm.adminStateCh:
			err := h.changeadminState(stateOp.State)
			if err == nil {
				switch stateOp.State {
				case adminStateDown:
					m, _ := fsm.sendEstablishedNotification(bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, stateOp.Communication))
					return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmAdminDown, notificationBody(m), nil)
				case adminStatePfxCt:
					m, _ := fsm.sendEstablishedNotification(bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED, nil))
					return bgp.BGP_FSM_IDLE, newfsmStateReason(fsmAdminDown, notificationBody(m), nil)
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
			h.allowLoopback = remoteAddr.IsLoopback() && localAddr.IsLoopback()

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
		case fsmAdminDown:
			if fsm.outgoingConnMgr != nil {
				fsm.outgoingConnMgr.stop(nil)
			}
		}

		if ctx.Err() != nil {
			break
		}

		switch nextState {
		case bgp.BGP_FSM_IDLE:
			if fsm.outgoingConnMgr != nil && fsm.outgoingConnMgr.keepForIdle() {
				// Our own connection is still in progress, so only the
				// other connection failed. Leave Idle at once, so that
				// active() takes our connection, and keep the backoff.
				// Otherwise keepForIdle() stopped the manager: in Idle
				// we make no connection to the peer.
				fsm.idleHoldTime = 0
			} else {
				conf := fsm.pConf.ReadOnly()
				fsm.idleHoldTime, fsm.idleHoldBackoff = nextIdleHoldTime(fsm.idleHoldBackoff, conf.Timers.Config.IdleHoldTimeAfterReset, reason)
			}
		case bgp.BGP_FSM_ESTABLISHED:
			fsm.idleHoldBackoff = idleHoldTimeInitial
			// The manager may still run: it sent its OPEN before the
			// incoming connection got the peer's OPEN, so opensent() did
			// not stop it. Stop it now, or it opens connections to the
			// peer while the session is established. RFC 4271 Section 6.8
			// says: "Unless allowed via configuration, a connection
			// collision with an existing BGP connection that is in the
			// Established state causes closing of the newly created
			// connection."
			if fsm.outgoingConnMgr != nil {
				fsm.outgoingConnMgr.stop(bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION, nil))
			}
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
	// Only the FSM goroutine writes adminState, so it cannot change
	// between Load and Store.
	if fsm.adminState.Load() != s {
		fsm.adminState.Store(s)
		fsm.logger.Debug("admin state changed",
			slog.String("State", fsm.state.String()),
			slog.String("adminState", s.String()))

		h.fsm.lock.Lock()
		conf := fsm.pConf.ReadCopy()
		conf.State.AdminDown = s != adminStateUp
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
