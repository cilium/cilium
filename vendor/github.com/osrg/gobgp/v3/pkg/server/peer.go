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
	"fmt"
	"net"
	"time"

	"github.com/osrg/gobgp/v3/internal/pkg/config"
	"github.com/osrg/gobgp/v3/internal/pkg/table"
	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

const (
	flopThreshold = time.Second * 30
)

type peerGroup struct {
	Conf             *config.PeerGroup
	members          map[string]config.Neighbor
	dynamicNeighbors map[string]*config.DynamicNeighbor
}

func newPeerGroup(c *config.PeerGroup) *peerGroup {
	return &peerGroup{
		Conf:             c,
		members:          make(map[string]config.Neighbor),
		dynamicNeighbors: make(map[string]*config.DynamicNeighbor),
	}
}

func (pg *peerGroup) AddMember(c config.Neighbor) {
	pg.members[c.State.NeighborAddress] = c
}

func (pg *peerGroup) DeleteMember(c config.Neighbor) {
	delete(pg.members, c.State.NeighborAddress)
}

func (pg *peerGroup) AddDynamicNeighbor(c *config.DynamicNeighbor) {
	pg.dynamicNeighbors[c.Config.Prefix] = c
}

func (pg *peerGroup) DeleteDynamicNeighbor(prefix string) {
	delete(pg.dynamicNeighbors, prefix)
}

func newDynamicPeer(g *config.Global, neighborAddress string, pg *config.PeerGroup, loc *table.TableManager, policy *table.RoutingPolicy, logger log.Logger) *peer {
	conf := config.Neighbor{
		Config: config.NeighborConfig{
			PeerGroup: pg.Config.PeerGroupName,
		},
		State: config.NeighborState{
			NeighborAddress: neighborAddress,
		},
		Transport: config.Transport{
			Config: config.TransportConfig{
				PassiveMode: true,
			},
		},
	}
	if err := config.OverwriteNeighborConfigWithPeerGroup(&conf, pg); err != nil {
		logger.Debug("Can't overwrite neighbor config",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"Error": err})
		return nil
	}
	if err := config.SetDefaultNeighborConfigValues(&conf, pg, g); err != nil {
		logger.Debug("Can't set default config",
			log.Fields{
				"Topic": "Peer",
				"Key":   neighborAddress,
				"Error": err})
		return nil
	}
	peer := newPeer(g, &conf, loc, policy, logger)
	peer.fsm.lock.Lock()
	peer.fsm.state = bgp.BGP_FSM_ACTIVE
	peer.fsm.lock.Unlock()
	return peer
}

type peer struct {
	tableId           string
	fsm               *fsm
	adjRibIn          *table.AdjRib
	policy            *table.RoutingPolicy
	localRib          *table.TableManager
	prefixLimitWarned map[bgp.RouteFamily]bool
	llgrEndChs        []chan struct{}
}

func newPeer(g *config.Global, conf *config.Neighbor, loc *table.TableManager, policy *table.RoutingPolicy, logger log.Logger) *peer {
	peer := &peer{
		localRib:          loc,
		policy:            policy,
		fsm:               newFSM(g, conf, logger),
		prefixLimitWarned: make(map[bgp.RouteFamily]bool),
	}
	if peer.isRouteServerClient() {
		peer.tableId = conf.State.NeighborAddress
	} else {
		peer.tableId = table.GLOBAL_RIB_NAME
	}
	rfs, _ := config.AfiSafis(conf.AfiSafis).ToRfList()
	peer.adjRibIn = table.NewAdjRib(peer.fsm.logger, rfs)
	return peer
}

func (peer *peer) AS() uint32 {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.State.PeerAs
}

func (peer *peer) ID() string {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.State.NeighborAddress
}

func (peer *peer) RouterID() string {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	if peer.fsm.peerInfo.ID != nil {
		return peer.fsm.peerInfo.ID.String()
	}
	return ""
}

func (peer *peer) TableID() string {
	return peer.tableId
}

func (peer *peer) isIBGPPeer() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.State.PeerType == config.PEER_TYPE_INTERNAL
}

func (peer *peer) isRouteServerClient() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.RouteServer.Config.RouteServerClient
}

func (peer *peer) isSecondaryRouteEnabled() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.RouteServer.Config.RouteServerClient && peer.fsm.pConf.RouteServer.Config.SecondaryRoute
}

func (peer *peer) isRouteReflectorClient() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.RouteReflector.Config.RouteReflectorClient
}

func (peer *peer) isGracefulRestartEnabled() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.GracefulRestart.State.Enabled
}

func (peer *peer) getAddPathMode(family bgp.RouteFamily) bgp.BGPAddPathMode {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	if mode, y := peer.fsm.rfMap[family]; y {
		return mode
	}
	return bgp.BGP_ADD_PATH_NONE
}

func (peer *peer) isAddPathReceiveEnabled(family bgp.RouteFamily) bool {
	return (peer.getAddPathMode(family) & bgp.BGP_ADD_PATH_RECEIVE) > 0
}

func (peer *peer) isAddPathSendEnabled(family bgp.RouteFamily) bool {
	return (peer.getAddPathMode(family) & bgp.BGP_ADD_PATH_SEND) > 0
}

func (peer *peer) isDynamicNeighbor() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	return peer.fsm.pConf.Config.NeighborAddress == "" && peer.fsm.pConf.Config.NeighborInterface == ""
}

func (peer *peer) recvedAllEOR() bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	for _, a := range peer.fsm.pConf.AfiSafis {
		if s := a.MpGracefulRestart.State; s.Enabled && !s.EndOfRibReceived {
			return false
		}
	}
	return true
}

func (peer *peer) configuredRFlist() []bgp.RouteFamily {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	rfs, _ := config.AfiSafis(peer.fsm.pConf.AfiSafis).ToRfList()
	return rfs
}

func (peer *peer) negotiatedRFList() []bgp.RouteFamily {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	l := make([]bgp.RouteFamily, 0, len(peer.fsm.rfMap))
	for family := range peer.fsm.rfMap {
		l = append(l, family)
	}
	return l
}

func (peer *peer) toGlobalFamilies(families []bgp.RouteFamily) []bgp.RouteFamily {
	id := peer.ID()
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	if peer.fsm.pConf.Config.Vrf != "" {
		fs := make([]bgp.RouteFamily, 0, len(families))
		for _, f := range families {
			switch f {
			case bgp.RF_IPv4_UC:
				fs = append(fs, bgp.RF_IPv4_VPN)
			case bgp.RF_IPv6_UC:
				fs = append(fs, bgp.RF_IPv6_VPN)
			case bgp.RF_FS_IPv4_UC:
				fs = append(fs, bgp.RF_FS_IPv4_VPN)
			case bgp.RF_FS_IPv6_UC:
				fs = append(fs, bgp.RF_FS_IPv6_VPN)
			default:
				peer.fsm.logger.Warn("invalid family configured for neighbor with vrf",
					log.Fields{
						"Topic":  "Peer",
						"Key":    id,
						"Family": f,
						"VRF":    peer.fsm.pConf.Config.Vrf})
			}
		}
		families = fs
	}
	return families
}

func classifyFamilies(all, part []bgp.RouteFamily) ([]bgp.RouteFamily, []bgp.RouteFamily) {
	a := []bgp.RouteFamily{}
	b := []bgp.RouteFamily{}
	for _, f := range all {
		p := true
		for _, g := range part {
			if f == g {
				p = false
				a = append(a, f)
				break
			}
		}
		if p {
			b = append(b, f)
		}
	}
	return a, b
}

func (peer *peer) forwardingPreservedFamilies() ([]bgp.RouteFamily, []bgp.RouteFamily) {
	peer.fsm.lock.RLock()
	list := []bgp.RouteFamily{}
	for _, a := range peer.fsm.pConf.AfiSafis {
		if s := a.MpGracefulRestart.State; s.Enabled && s.Received {
			list = append(list, a.State.Family)
		}
	}
	peer.fsm.lock.RUnlock()
	return classifyFamilies(peer.configuredRFlist(), list)
}

func (peer *peer) llgrFamilies() ([]bgp.RouteFamily, []bgp.RouteFamily) {
	peer.fsm.lock.RLock()
	list := []bgp.RouteFamily{}
	for _, a := range peer.fsm.pConf.AfiSafis {
		if a.LongLivedGracefulRestart.State.Enabled {
			list = append(list, a.State.Family)
		}
	}
	peer.fsm.lock.RUnlock()
	return classifyFamilies(peer.configuredRFlist(), list)
}

func (peer *peer) isLLGREnabledFamily(family bgp.RouteFamily) bool {
	peer.fsm.lock.RLock()
	llgrEnabled := peer.fsm.pConf.GracefulRestart.Config.LongLivedEnabled
	peer.fsm.lock.RUnlock()
	if !llgrEnabled {
		return false
	}
	fs, _ := peer.llgrFamilies()
	for _, f := range fs {
		if f == family {
			return true
		}
	}
	return false
}

func (peer *peer) llgrRestartTime(family bgp.RouteFamily) uint32 {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	for _, a := range peer.fsm.pConf.AfiSafis {
		if a.State.Family == family {
			return a.LongLivedGracefulRestart.State.PeerRestartTime
		}
	}
	return 0
}

func (peer *peer) llgrRestartTimerExpired(family bgp.RouteFamily) bool {
	peer.fsm.lock.RLock()
	defer peer.fsm.lock.RUnlock()
	all := true
	for _, a := range peer.fsm.pConf.AfiSafis {
		if a.State.Family == family {
			a.LongLivedGracefulRestart.State.PeerRestartTimerExpired = true
		}
		s := a.LongLivedGracefulRestart.State
		if s.Received && !s.PeerRestartTimerExpired {
			all = false
		}
	}
	return all
}

func (peer *peer) markLLGRStale(fs []bgp.RouteFamily) []*table.Path {
	return peer.adjRibIn.MarkLLGRStaleOrDrop(fs)
}

func (peer *peer) stopPeerRestarting() {
	peer.fsm.lock.Lock()
	defer peer.fsm.lock.Unlock()
	peer.fsm.pConf.GracefulRestart.State.PeerRestarting = false
	for _, ch := range peer.llgrEndChs {
		close(ch)
	}
	peer.llgrEndChs = make([]chan struct{}, 0)

}

func (peer *peer) filterPathFromSourcePeer(path, old *table.Path) *table.Path {
	// Consider 3 peers - A, B, C and prefix P originated by C. Parallel eBGP
	// sessions exist between A & B, and both have a single session with C.
	//
	// When A receives the withdraw from C, we enter this func for each peer of
	// A, with the following:
	// peer: [C, B #1, B #2]
	// path: new best for P facing B
	// old: old best for P facing C
	//
	// Our comparison between peer identifier and path source ID must be router
	// ID-based (not neighbor address), otherwise we will return early. If we
	// return early for one of the two sessions facing B
	// (whichever is not the new best path), we fail to send a withdraw towards
	// B, and the route is "stuck".
	// TODO: considerations for RFC6286
	if peer.RouterID() != path.GetSource().ID.String() {
		return path
	}

	// Note: Multiple paths having the same prefix could exist the withdrawals
	// list in the case of Route Server setup with import policies modifying
	// paths. In such case, gobgp sends duplicated update messages; withdraw
	// messages for the same prefix.
	if !peer.isRouteServerClient() {
		if peer.isRouteReflectorClient() && path.GetRouteFamily() == bgp.RF_RTC_UC {
			// When the peer is a Route Reflector client and the given path
			// contains the Route Tartget Membership NLRI, the path should not
			// be withdrawn in order to signal the client to distribute routes
			// with the specific RT to Route Reflector.
			return path
		} else if !path.IsWithdraw && old != nil && old.GetSource().Address.String() != peer.ID() {
			// Say, peer A and B advertized same prefix P, and best path
			// calculation chose a path from B as best. When B withdraws prefix
			// P, best path calculation chooses the path from A as best. For
			// peers other than A, this path should be advertised (as implicit
			// withdrawal). However for A, we should advertise the withdrawal
			// path. Thing is same when peer A and we advertized prefix P (as
			// local route), then, we withdraws the prefix.
			return old.Clone(true)
		}
	}
	peer.fsm.logger.Debug("From me, ignore",
		log.Fields{
			"Topic": "Peer",
			"Key":   peer.ID(),
			"Data":  path})
	return nil
}

func (peer *peer) doPrefixLimit(k bgp.RouteFamily, c *config.PrefixLimitConfig) *bgp.BGPMessage {
	if maxPrefixes := int(c.MaxPrefixes); maxPrefixes > 0 {
		count := peer.adjRibIn.Count([]bgp.RouteFamily{k})
		pct := int(c.ShutdownThresholdPct)
		if pct > 0 && !peer.prefixLimitWarned[k] && count > (maxPrefixes*pct/100) {
			peer.prefixLimitWarned[k] = true
			peer.fsm.logger.Warn("prefix limit reached",
				log.Fields{
					"Topic":  "Peer",
					"Key":    peer.ID(),
					"Family": k.String(),
					"Pct":    pct})
		}
		if count > maxPrefixes {
			peer.fsm.logger.Warn("prefix limit reached",
				log.Fields{
					"Topic":  "Peer",
					"Key":    peer.ID(),
					"Family": k.String()})
			return bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED, nil)
		}
	}
	return nil

}

func (peer *peer) updatePrefixLimitConfig(c []config.AfiSafi) error {
	peer.fsm.lock.RLock()
	x := peer.fsm.pConf.AfiSafis
	peer.fsm.lock.RUnlock()
	y := c
	if len(x) != len(y) {
		return fmt.Errorf("changing supported afi-safi is not allowed")
	}
	m := make(map[bgp.RouteFamily]config.PrefixLimitConfig)
	for _, e := range x {
		m[e.State.Family] = e.PrefixLimit.Config
	}
	for _, e := range y {
		if p, ok := m[e.State.Family]; !ok {
			return fmt.Errorf("changing supported afi-safi is not allowed")
		} else if !p.Equal(&e.PrefixLimit.Config) {
			peer.fsm.logger.Warn("update prefix limit configuration",
				log.Fields{
					"Topic":                   "Peer",
					"Key":                     peer.ID(),
					"AddressFamily":           e.Config.AfiSafiName,
					"OldMaxPrefixes":          p.MaxPrefixes,
					"NewMaxPrefixes":          e.PrefixLimit.Config.MaxPrefixes,
					"OldShutdownThresholdPct": p.ShutdownThresholdPct,
					"NewShutdownThresholdPct": e.PrefixLimit.Config.ShutdownThresholdPct})
			peer.prefixLimitWarned[e.State.Family] = false
			if msg := peer.doPrefixLimit(e.State.Family, &e.PrefixLimit.Config); msg != nil {
				sendfsmOutgoingMsg(peer, nil, msg, true)
			}
		}
	}
	peer.fsm.lock.Lock()
	peer.fsm.pConf.AfiSafis = c
	peer.fsm.lock.Unlock()
	return nil
}

func (peer *peer) handleUpdate(e *fsmMsg) ([]*table.Path, []bgp.RouteFamily, *bgp.BGPMessage) {
	m := e.MsgData.(*bgp.BGPMessage)
	update := m.Body.(*bgp.BGPUpdate)
	peer.fsm.logger.Debug("received update",
		log.Fields{
			"Topic":       "Peer",
			"Key":         peer.fsm.pConf.State.NeighborAddress,
			"nlri":        update.NLRI,
			"withdrawals": update.WithdrawnRoutes,
			"attributes":  update.PathAttributes})
	peer.fsm.lock.Lock()
	peer.fsm.pConf.Timers.State.UpdateRecvTime = time.Now().Unix()
	peer.fsm.lock.Unlock()
	if len(e.PathList) > 0 {
		paths := make([]*table.Path, 0, len(e.PathList))
		eor := []bgp.RouteFamily{}
		for _, path := range e.PathList {
			if path.IsEOR() {
				family := path.GetRouteFamily()
				peer.fsm.logger.Debug("EOR received",
					log.Fields{
						"Topic":         "Peer",
						"Key":           peer.ID(),
						"AddressFamily": family})
				eor = append(eor, family)
				continue
			}
			// RFC4271 9.1.2 Phase 2: Route Selection
			//
			// If the AS_PATH attribute of a BGP route contains an AS loop, the BGP
			// route should be excluded from the Phase 2 decision function.
			if aspath := path.GetAsPath(); aspath != nil {
				peer.fsm.lock.RLock()
				localAS := peer.fsm.peerInfo.LocalAS
				allowOwnAS := int(peer.fsm.pConf.AsPathOptions.Config.AllowOwnAs)
				peer.fsm.lock.RUnlock()
				if hasOwnASLoop(localAS, allowOwnAS, aspath) {
					path.SetRejected(true)
					continue
				}
			}
			// RFC4456 8. Avoiding Routing Information Loops
			// A router that recognizes the ORIGINATOR_ID attribute SHOULD
			// ignore a route received with its BGP Identifier as the ORIGINATOR_ID.
			isIBGPPeer := peer.isIBGPPeer()
			peer.fsm.lock.RLock()
			routerId := peer.fsm.gConf.Config.RouterId
			peer.fsm.lock.RUnlock()
			if isIBGPPeer {
				if id := path.GetOriginatorID(); routerId == id.String() {
					peer.fsm.logger.Debug("Originator ID is mine, ignore",
						log.Fields{
							"Topic":        "Peer",
							"Key":          peer.ID(),
							"OriginatorID": id,
							"Data":         path})
					path.SetRejected(true)
					continue
				}
			}
			paths = append(paths, path)
		}
		peer.adjRibIn.Update(e.PathList)
		peer.fsm.lock.RLock()
		peerAfiSafis := peer.fsm.pConf.AfiSafis
		peer.fsm.lock.RUnlock()
		for _, af := range peerAfiSafis {
			if msg := peer.doPrefixLimit(af.State.Family, &af.PrefixLimit.Config); msg != nil {
				return nil, nil, msg
			}
		}
		return paths, eor, nil
	}
	return nil, nil, nil
}

func (peer *peer) startFSMHandler() {
	handler := newFSMHandler(peer.fsm, peer.fsm.outgoingCh)
	peer.fsm.lock.Lock()
	peer.fsm.h = handler
	peer.fsm.lock.Unlock()
}

func (peer *peer) StaleAll(rfList []bgp.RouteFamily) []*table.Path {
	return peer.adjRibIn.StaleAll(rfList)
}

func (peer *peer) PassConn(conn *net.TCPConn) {
	select {
	case peer.fsm.connCh <- conn:
	default:
		conn.Close()
		peer.fsm.logger.Warn("accepted conn is closed to avoid be blocked",
			log.Fields{
				"Topic": "Peer",
				"Key":   peer.ID()})
	}
}

func (peer *peer) DropAll(rfList []bgp.RouteFamily) []*table.Path {
	return peer.adjRibIn.Drop(rfList)
}
