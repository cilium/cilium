// Copyright (C) 2015-2021 Nippon Telegraph and Telephone Corporation.
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
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/packet/bmp"
)

// bmpAddPathMarshallingOption returns the options for encoding an NLRI of
// family with its path identifier in front.
func bmpAddPathMarshallingOption(family bgp.Family) []*bgp.MarshallingOption {
	return []*bgp.MarshallingOption{{
		AddPath: map[bgp.Family]bgp.BGPAddPathMode{
			family: bgp.BGP_ADD_PATH_BOTH,
		},
	}}
}

// bmpAdjRIBInMarshallingOption returns the options for encoding a path of a
// peer's Adj-RIB-In. The receiver decodes Route Monitoring messages with the
// capabilities of the OPEN messages the Peer Up carries, so the encoding here
// has to follow what the session negotiated. Only the receive direction
// matters: gobgp reports what the peer sent it.
//
// A nil neighbor is a path that no BGP session brought in, so no capability
// was negotiated for it and no Peer Up was ever sent.
func bmpAdjRIBInMarshallingOption(n *oc.Neighbor, family bgp.Family) []*bgp.MarshallingOption {
	if n == nil || !n.IsAddPathReceiveEnabled(family) {
		return nil
	}
	return bmpAddPathMarshallingOption(family)
}

// bmpRouteMonitoring builds the Route Monitoring messages for one Adj-RIB-In
// watch event. A live update carries the payload received on the wire and is
// forwarded as it is. The initial dump and the withdrawals gobgp generates
// itself carry paths instead, so the UPDATE is built here.
//
// A path whose UPDATE cannot be serialized is dropped. Only that path is lost.
// The BMP session stays up, because one bad path is no reason to stop
// reporting the rest.
//
// An event with no neighbor is not reported at all. The post-policy initial
// dump groups the Loc-RIB by the source of each path, and a locally originated
// path has none, so its group carries a zero PeerInfo and no neighbor. Route
// Monitoring for it would use a per-peer header of all zeros that no Peer Up
// ever announced, and the End-of-RIB of that group would pair with no Peer Up
// either. RFC 9069 section 1 replaced RFC 7854 section 8.2 ("Locally
// Originated Routes"): such routes belong to the Loc-RIB instance peer, which
// bmpLocRIBRouteMonitoring reports. A post-policy Adj-RIB-In holds no locally
// originated route anyway. Every other event carries a neighbor.
func bmpRouteMonitoring(msg *watchEventUpdate, logger *slog.Logger) []*bmp.BMPMessage {
	if msg.Neighbor == nil {
		return nil
	}

	info := &table.PeerInfo{
		Address: msg.PeerAddress,
		AS:      msg.PeerAS,
		ID:      msg.PeerID,
	}
	if msg.Payload != nil {
		return []*bmp.BMPMessage{
			bmpPeerRoute(bmp.BMP_PEER_TYPE_GLOBAL, msg.PostPolicy, 0, msg.FourBytesAs, info, msg.Timestamp.Unix(), msg.Payload),
		}
	}

	msgs := make([]*bmp.BMPMessage, 0, len(msg.PathList))
	for _, path := range msg.PathList {
		options := bmpAdjRIBInMarshallingOption(msg.Neighbor, path.GetFamily())
		for _, u := range table.CreateUpdateMsgFromAdjRIBInPaths([]*table.Path{path}, options...) {
			payload, err := u.Serialize(options...)
			if err != nil {
				logger.Warn("failed to serialize bmp route monitoring message",
					slog.String("Topic", "bmp"),
					slog.Any("Path", path),
					slog.String("Error", err.Error()))
				continue
			}
			msgs = append(msgs, bmpPeerRoute(bmp.BMP_PEER_TYPE_GLOBAL, msg.PostPolicy, 0, true, info, path.GetTimestamp().Unix(), payload))
		}
	}
	return msgs
}

// bmpLocRIBRouteMonitoring builds the Loc-RIB Route Monitoring messages
// (RFC 9069) for one best path event. A path that cannot be serialized is
// dropped, as in bmpRouteMonitoring.
func bmpLocRIBRouteMonitoring(msg *watchEventBestPath, info *table.PeerInfo, logger *slog.Logger) []*bmp.BMPMessage {
	paths := locRIBPathsForBMP(msg)
	msgs := make([]*bmp.BMPMessage, 0, len(paths))
	for _, p := range paths {
		if p == nil {
			continue
		}
		options := bmpAddPathMarshallingOption(p.GetFamily())
		for _, u := range table.CreateUpdateMsgFromPaths([]*table.Path{p}, options...) {
			payload, err := u.Serialize(options...)
			if err != nil {
				logger.Warn("failed to serialize bmp loc-rib route monitoring message",
					slog.String("Topic", "bmp"),
					slog.Any("Path", p),
					slog.String("Error", err.Error()))
				continue
			}
			msgs = append(msgs, bmpPeerRoute(bmp.BMP_PEER_TYPE_LOCAL_RIB, false, 0, true, info, p.GetTimestamp().Unix(), payload))
		}
	}
	return msgs
}

func (b *bmpClient) tryConnect() *net.TCPConn {
	interval := 1
	for {
		b.s.logger.Debug("Connecting to BMP server",
			slog.String("Topic", "bmp"),
			slog.String("Key", b.host.String()))
		conn, err := net.Dial("tcp", b.host.String())
		if err != nil {
			select {
			case <-b.dead:
				return nil
			default:
			}
			time.Sleep(time.Duration(interval) * time.Second)
			if interval < 30 {
				interval *= 2
			}
		} else {
			b.s.logger.Debug("Connected to BMP server",
				slog.String("Topic", "bmp"),
				slog.String("Key", b.host.String()))
			return conn.(*net.TCPConn)
		}
	}
}

func (b *bmpClient) Stop() {
	close(b.dead)
}

func (b *bmpClient) loop() {
	for {
		conn := b.tryConnect()
		if conn == nil {
			break
		}
		atomic.StoreInt64(&b.uptime, time.Now().Unix())

		if func() bool {
			defer func() {
				atomic.StoreInt64(&b.downtime, time.Now().Unix())
				conn.Close()
			}()
			ops := []WatchOption{WatchPeer()}
			if b.c.RouteMonitoringPolicy == oc.BMP_ROUTE_MONITORING_POLICY_TYPE_BOTH {
				b.s.logger.Warn("both option for route-monitoring-policy is obsoleted", slog.String("Topic", "bmp"))
			}
			if b.c.RouteMonitoringPolicy == oc.BMP_ROUTE_MONITORING_POLICY_TYPE_PRE_POLICY || b.c.RouteMonitoringPolicy == oc.BMP_ROUTE_MONITORING_POLICY_TYPE_ALL {
				ops = append(ops, WatchUpdate(true, "", ""))
				// Adj-RIB-In withdrawals generated on peer down / graceful-restart
				// expiry are not received on the wire, so they arrive on a separate
				// watch type.
				ops = append(ops, WatchAdjInWithdraw())
			}
			if b.c.RouteMonitoringPolicy == oc.BMP_ROUTE_MONITORING_POLICY_TYPE_POST_POLICY || b.c.RouteMonitoringPolicy == oc.BMP_ROUTE_MONITORING_POLICY_TYPE_ALL {
				ops = append(ops, WatchPostUpdate(true, "", ""))
			}
			if b.c.RouteMonitoringPolicy == oc.BMP_ROUTE_MONITORING_POLICY_TYPE_LOCAL_RIB || b.c.RouteMonitoringPolicy == oc.BMP_ROUTE_MONITORING_POLICY_TYPE_ALL {
				ops = append(ops, WatchBestPath(true))
			}
			if b.c.RouteMirroringEnabled {
				ops = append(ops, watchRecvMessage())
			}
			w, err := b.s.watch(ops...)
			if err != nil {
				// the BGP server has stopped, so there is nothing left to watch.
				b.s.logger.Warn("failed to start bmp watcher",
					slog.String("Topic", "bmp"),
					slog.String("Key", b.host.String()),
					slog.String("Error", err.Error()))
				return true
			}
			defer w.Stop()

			var tickerCh <-chan time.Time
			if b.c.StatisticsTimeout == 0 {
				b.s.logger.Debug("statistics reports disabled", slog.String("Topic", "bmp"))
			} else {
				t := time.NewTicker(time.Duration(b.c.StatisticsTimeout) * time.Second)
				defer t.Stop()
				tickerCh = t.C
			}

			write := func(msg *bmp.BMPMessage) error {
				buf, _ := msg.Serialize()
				_, err := conn.Write(buf)
				if err != nil {
					b.s.logger.Warn("failed to write to bmp server",
						slog.String("Topic", "bmp"),
						slog.String("Key", b.host.String()),
						slog.String("Message", err.Error()))
				}
				return err
			}

			tlv := []bmp.BMPInfoTLVInterface{
				bmp.NewBMPInfoTLVString(bmp.BMP_INIT_TLV_TYPE_SYS_NAME, b.c.SysName),
				bmp.NewBMPInfoTLVString(bmp.BMP_INIT_TLV_TYPE_SYS_DESCR, b.c.SysDescr),
			}

			if err := write(bmp.NewBMPInitiation(tlv)); err != nil {
				return false
			}

			// RFC9069 (minimal): announce a single Loc-RIB instance only when
			// route-monitoring-policy includes local-rib.
			sentLocRIBPeerUp := false
			if b.c.RouteMonitoringPolicy == oc.BMP_ROUTE_MONITORING_POLICY_TYPE_LOCAL_RIB || b.c.RouteMonitoringPolicy == oc.BMP_ROUTE_MONITORING_POLICY_TYPE_ALL {
				// For now, use PD=0 and VRF/Table Name="global".
				if err := write(bmpLocRIBPeerUp(
					b.s.bgpConfig.Global.Config.As,
					b.s.bgpConfig.Global.Config.RouterId,
					"global",
					0,
					time.Now().Unix(),
					b.s.globalRib.GetRFlist(),
				)); err != nil {
					return false
				}
				sentLocRIBPeerUp = true
			}

			for {
				select {
				case ev := <-w.Event():
					switch msg := ev.(type) {
					case *watchEventUpdate:
						for _, m := range bmpRouteMonitoring(msg, b.s.logger) {
							if err := write(m); err != nil {
								return false
							}
						}
					case *watchEventBestPath:
						info := &table.PeerInfo{
							Address: netip.IPv4Unspecified(),
							AS:      b.s.bgpConfig.Global.Config.As,
							ID:      b.s.bgpConfig.Global.Config.RouterId,
						}
						for _, m := range bmpLocRIBRouteMonitoring(msg, info, b.s.logger) {
							if err := write(m); err != nil {
								return false
							}
						}
					case *watchEventPeer:
						if msg.Type != apiutil.PEER_EVENT_END_OF_INIT {
							if msg.State == bgp.BGP_FSM_ESTABLISHED {
								if err := write(bmpPeerUp(msg, bmp.BMP_PEER_TYPE_GLOBAL, false, 0)); err != nil {
									return false
								}
							} else if msg.Type != apiutil.PEER_EVENT_INIT && msg.OldState == bgp.BGP_FSM_ESTABLISHED {
								if err := write(bmpPeerDown(msg, bmp.BMP_PEER_TYPE_GLOBAL, false, 0)); err != nil {
									return false
								}
							}
						}
					case *watchEventMessage:
						info := &table.PeerInfo{
							Address: msg.PeerAddress,
							AS:      msg.PeerAS,
							ID:      msg.PeerID,
						}
						if err := write(bmpPeerRouteMirroring(bmp.BMP_PEER_TYPE_GLOBAL, 0, info, msg.Timestamp.Unix(), msg.Payload)); err != nil {
							return false
						}
					}
				case <-tickerCh:
					var err error
					listErr := b.s.ListPeer(context.Background(), &api.ListPeerRequest{EnableAdvertised: true},
						func(peer *api.Peer) {
							if err == nil && peer.State.SessionState == api.PeerState_SESSION_STATE_ESTABLISHED {
								err = write(bmpPeerStats(bmp.BMP_PEER_TYPE_GLOBAL, 0, time.Now().Unix(), peer))
							}
						})
					if listErr != nil || err != nil {
						return false
					}
				case <-b.dead:
					// RFC9069 (minimal): close the announced Loc-RIB instance.
					if sentLocRIBPeerUp {
						_ = write(bmpLocRIBPeerDown(b.s.bgpConfig.Global.Config.As, b.s.bgpConfig.Global.Config.RouterId, "global", 0, time.Now().Unix()))
					}
					term := bmp.NewBMPTermination([]bmp.BMPTermTLVInterface{
						bmp.NewBMPTermTLV16(bmp.BMP_TERM_TLV_TYPE_REASON, bmp.BMP_TERM_REASON_PERMANENTLY_ADMIN),
					})
					if err := write(term); err != nil {
						return false
					}
					return true
				}
			}
		}() {
			return
		}
	}
}

func bmpLocRIBPeerUp(localAS uint32, routerID netip.Addr, tableName string, peerDist uint64, timestamp int64, families []bgp.Family) *bmp.BMPMessage {
	const asTrans uint16 = 23456

	myAS := asTrans
	opts := []bgp.OptionParameterInterface{}
	if localAS <= 0xffff {
		myAS = uint16(localAS)
	}
	// RFC 9069 5.2: "Capabilities MUST include the 4-octet ASN and all necessary
	// capabilities to represent the Loc-RIB Route Monitoring messages." The
	// 4-octet ASN capability is therefore advertised unconditionally, not only
	// when the ASN does not fit in the 2-octet My Autonomous System field.
	opts = append(opts, bgp.NewOptionParameterCapability([]bgp.ParameterCapabilityInterface{
		bgp.NewCapFourOctetASNumber(localAS),
	}))
	// Loc-RIB Route Monitoring messages are always marshalled with
	// BGP_ADD_PATH_BOTH (see bmpAddPathMarshallingOption), so the receiver always
	// needs the ADD-PATH capability to decode their NLRIs. Advertising it only
	// when global multipath happened to be enabled left the fabricated OPEN
	// describing an encoding that was not the one on the wire, and every NLRI was
	// then parsed 4 octets out of step.
	//
	// The tuple is advertised for every family the Loc-RIB holds a table for,
	// which is every family gobgp supports. A narrower list would have to be
	// revised whenever the first route of a family is installed, and this Peer
	// Up is sent once, when the BMP session comes up. RFC 9069 has no way to
	// amend the capabilities of a peer that is already up.
	tuples := make([]*bgp.CapAddPathTuple, 0, len(families))
	for _, f := range families {
		tuples = append(tuples, bgp.NewCapAddPathTuple(f, bgp.BGP_ADD_PATH_BOTH))
	}
	opts = append(opts, bgp.NewOptionParameterCapability([]bgp.ParameterCapabilityInterface{
		bgp.NewCapAddPath(tuples),
	}))

	open, _ := bgp.NewBGPOpenMessage(myAS, 90, routerID, opts)

	// RFC 9069 5.1: for a Loc-RIB Instance Peer only the Peer Address is
	// zero-filled. The Peer AS is "the primary router BGP autonomous system
	// number" and the Peer BGP ID is "the global instance router-id". They must
	// match the header the Route Monitoring messages carry (see bmpPeerRoute),
	// otherwise a receiver cannot correlate this Peer Up with them and loses the
	// capabilities negotiated above.
	ph := bmp.NewBMPPeerHeader(
		bmp.BMP_PEER_TYPE_LOCAL_RIB,
		0,
		peerDist,
		netip.Addr{},
		localAS,
		routerID,
		float64(timestamp),
	)
	return bmp.NewBMPPeerUpNotification(
		*ph,
		netip.Addr{},
		0,
		0,
		open,
		open,
		bmp.NewBMPInfoTLVString(bmp.BMP_INIT_TLV_TYPE_VRF_TABLE_NAME, tableName),
	)
}

func bmpLocRIBPeerDown(localAS uint32, routerID netip.Addr, tableName string, peerDist uint64, timestamp int64) *bmp.BMPMessage {
	// RFC 9069 5.1: as in bmpLocRIBPeerUp, only the Peer Address is zero-filled.
	// The Peer AS and Peer BGP ID identify the router, so that a receiver can tie
	// this Peer Down to the Peer Up and the Route Monitoring messages for the
	// same Loc-RIB instance.
	ph := bmp.NewBMPPeerHeader(
		bmp.BMP_PEER_TYPE_LOCAL_RIB,
		0,
		peerDist,
		netip.Addr{},
		localAS,
		routerID,
		float64(timestamp),
	)
	return bmp.NewBMPPeerDownNotification(
		*ph,
		bmp.BMP_PEER_DOWN_REASON_TLV_FOLLOWS,
		nil,
		nil,
		bmp.NewBMPInfoTLVString(bmp.BMP_INIT_TLV_TYPE_VRF_TABLE_NAME, tableName),
	)
}

type bmpClient struct {
	s        *BgpServer
	dead     chan struct{}
	host     netip.AddrPort
	c        *oc.BmpServerConfig
	uptime   int64
	downtime int64
}

func bmpPeerUp(ev *watchEventPeer, t uint8, policy bool, pd uint64) *bmp.BMPMessage {
	var flags uint8 = 0
	if policy {
		flags |= bmp.BMP_PEER_FLAG_POST_POLICY
	}
	// TODO: use netip event strcutres. MustParseAddr is safe because they are valid IP addresses.
	ph := bmp.NewBMPPeerHeader(t, flags, pd, ev.PeerAddress, ev.PeerAS, ev.PeerID, float64(ev.Timestamp.Unix()))
	return bmp.NewBMPPeerUpNotification(*ph, ev.LocalAddress, ev.LocalPort, ev.PeerPort, ev.SentOpen, ev.RecvOpen)
}

func bmpPeerDown(ev *watchEventPeer, t uint8, policy bool, pd uint64) *bmp.BMPMessage {
	var flags uint8 = 0
	if policy {
		flags |= bmp.BMP_PEER_FLAG_POST_POLICY
	}
	ph := bmp.NewBMPPeerHeader(t, flags, pd, ev.PeerAddress, ev.PeerAS, ev.PeerID, float64(ev.Timestamp.Unix()))

	reasonCode := bmp.BMP_peerDownByUnknownReason
	switch ev.StateReason.Type {
	case fsmDying, fsmInvalidMsg, fsmNotificationSent, fsmHoldTimerExpired, fsmIdleTimerExpired, fsmRestartTimerExpired:
		reasonCode = bmp.BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION
	case fsmAdminDown:
		reasonCode = bmp.BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION
	case fsmNotificationRecv, fsmGracefulRestart, fsmHardReset:
		reasonCode = bmp.BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION
	case fsmReadFailed, fsmWriteFailed:
		reasonCode = bmp.BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION
	case fsmDeConfigured:
		reasonCode = bmp.BMP_PEER_DOWN_REASON_PEER_DE_CONFIGURED
	}
	return bmp.NewBMPPeerDownNotification(*ph, uint8(reasonCode), ev.StateReason.notificationMessage(), ev.StateReason.Data)
}

func bmpPeerRoute(t uint8, policy bool, pd uint64, fourBytesAs bool, peeri *table.PeerInfo, timestamp int64, payload []byte) *bmp.BMPMessage {
	var flags uint8 = 0
	if policy {
		flags |= bmp.BMP_PEER_FLAG_POST_POLICY
	}
	if !fourBytesAs {
		flags |= bmp.BMP_PEER_FLAG_TWO_AS
	}
	ph := bmp.NewBMPPeerHeader(t, flags, pd, peeri.Address, peeri.AS, peeri.ID, float64(timestamp))
	m := bmp.NewBMPRouteMonitoring(*ph, nil)
	body := m.Body.(*bmp.BMPRouteMonitoring)
	body.BGPUpdatePayload = payload
	return m
}

func bmpPeerStats(peerType uint8, peerDist uint64, timestamp int64, peer *api.Peer) *bmp.BMPMessage {
	var peerFlags uint8 = 0
	ph := bmp.NewBMPPeerHeader(peerType, peerFlags, peerDist, netip.MustParseAddr(peer.State.NeighborAddress), peer.State.PeerAsn, netip.MustParseAddr(peer.State.RouterId), float64(timestamp))
	received := uint64(0)
	accepted := uint64(0)
	for _, a := range peer.AfiSafis {
		received += a.State.Received
		accepted += a.State.Accepted
	}
	return bmp.NewBMPStatisticsReport(
		*ph,
		[]bmp.BMPStatsTLVInterface{
			bmp.NewBMPStatsTLV64(bmp.BMP_STAT_TYPE_ADJ_RIB_IN, received),
			bmp.NewBMPStatsTLV64(bmp.BMP_STAT_TYPE_LOC_RIB, accepted),
			bmp.NewBMPStatsTLV32(bmp.BMP_STAT_TYPE_WITHDRAW_UPDATE, uint32(peer.State.Messages.Received.WithdrawUpdate)),
			bmp.NewBMPStatsTLV32(bmp.BMP_STAT_TYPE_WITHDRAW_PREFIX, uint32(peer.State.Messages.Received.WithdrawPrefix)),
		},
	)
}

func bmpPeerRouteMirroring(peerType uint8, peerDist uint64, peerInfo *table.PeerInfo, timestamp int64, payload []byte) *bmp.BMPMessage {
	var peerFlags uint8 = 0
	ph := bmp.NewBMPPeerHeader(peerType, peerFlags, peerDist, peerInfo.Address, peerInfo.AS, peerInfo.ID, float64(timestamp))
	// RFC7854: BGP Message TLV MUST occur last in the list of TLVs
	tlv := bmp.NewBMPRouteMirrTLVBGPMsg(bmp.BMP_ROUTE_MIRRORING_TLV_TYPE_BGP_MSG, nil)
	tlv.Payload = payload
	return bmp.NewBMPRouteMirroring(*ph, []bmp.BMPRouteMirrTLVInterface{tlv})
}

func (b *bmpClientManager) addServer(c *oc.BmpServerConfig) error {
	host := netip.AddrPortFrom(c.Address, uint16(c.Port))
	if _, y := b.clientMap[host]; y {
		return fmt.Errorf("bmp client %s is already configured", host)
	}
	b.clientMap[host] = &bmpClient{
		s:    b.s,
		dead: make(chan struct{}),
		host: host,
		c:    c,
	}
	go b.clientMap[host].loop()
	return nil
}

func (b *bmpClientManager) deleteServer(c *oc.BmpServerConfig) error {
	host := netip.AddrPortFrom(c.Address, uint16(c.Port))
	if c, y := b.clientMap[host]; !y {
		return fmt.Errorf("bmp client %s isn't found", host)
	} else {
		c.Stop()
		delete(b.clientMap, host)
	}
	return nil
}

type bmpClientManager struct {
	s         *BgpServer
	clientMap map[netip.AddrPort]*bmpClient
}

func newBmpClientManager(s *BgpServer) *bmpClientManager {
	return &bmpClientManager{
		s:         s,
		clientMap: make(map[netip.AddrPort]*bmpClient),
	}
}
