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
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/eapache/channels"
	"github.com/google/uuid"
	"google.golang.org/grpc"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/internal/pkg/config"
	"github.com/osrg/gobgp/v3/internal/pkg/table"
	"github.com/osrg/gobgp/v3/internal/pkg/version"
	"github.com/osrg/gobgp/v3/internal/pkg/zebra"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/bmp"
)

type tcpListener struct {
	l  *net.TCPListener
	ch chan struct{}
}

func (l *tcpListener) Close() error {
	if err := l.l.Close(); err != nil {
		return err
	}
	<-l.ch
	return nil
}

// avoid mapped IPv6 address
func newTCPListener(logger log.Logger, address string, port uint32, bindToDev string, ch chan *net.TCPConn) (*tcpListener, error) {
	proto := "tcp4"
	family := syscall.AF_INET
	if ip := net.ParseIP(address); ip == nil {
		return nil, fmt.Errorf("can't listen on %s", address)
	} else if ip.To4() == nil {
		proto = "tcp6"
		family = syscall.AF_INET6
	}
	addr := net.JoinHostPort(address, strconv.Itoa(int(port)))

	var lc net.ListenConfig
	lc.Control = func(network, address string, c syscall.RawConn) error {
		if bindToDev != "" {
			err := setBindToDevSockopt(c, bindToDev)
			if err != nil {
				logger.Warn("failed to bind Listener to device ",
					log.Fields{
						"Topic":     "Peer",
						"Key":       addr,
						"BindToDev": bindToDev,
						"Error":     err})
				return err
			}
		}
		// Note: Set TTL=255 for incoming connection listener in order to accept
		// connection in case for the neighbor has TTL Security settings.
		err := setsockoptIpTtl(c, family, 255)
		if err != nil {
			logger.Warn("cannot set TTL (255) for TCPListener",
				log.Fields{
					"Topic": "Peer",
					"Key":   addr,
					"Err":   err})
		}
		return nil
	}

	l, err := lc.Listen(context.Background(), proto, addr)
	if err != nil {
		return nil, err
	}
	listener, ok := l.(*net.TCPListener)
	if !ok {
		err = fmt.Errorf("unexpected connection listener (not for TCP)")
		return nil, err
	}

	closeCh := make(chan struct{})
	go func() error {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				close(closeCh)
				if !errors.Is(err, net.ErrClosed) {
					logger.Warn("Failed to AcceptTCP",
						log.Fields{
							"Topic": "Peer",
							"Error": err,
						})
				}
				return err
			}
			ch <- conn
		}
	}()
	return &tcpListener{
		l:  listener,
		ch: closeCh,
	}, nil
}

type options struct {
	grpcAddress string
	grpcOption  []grpc.ServerOption
	logger      log.Logger
}

type ServerOption func(*options)

func GrpcListenAddress(addr string) ServerOption {
	return func(o *options) {
		o.grpcAddress = addr
	}
}

func GrpcOption(opt []grpc.ServerOption) ServerOption {
	return func(o *options) {
		o.grpcOption = opt
	}
}

func LoggerOption(logger log.Logger) ServerOption {
	return func(o *options) {
		o.logger = logger
	}
}

type BgpServer struct {
	apiServer    *server
	bgpConfig    config.Bgp
	acceptCh     chan *net.TCPConn
	incomings    []*channels.InfiniteChannel
	mgmtCh       chan *mgmtOp
	policy       *table.RoutingPolicy
	listeners    []*tcpListener
	neighborMap  map[string]*peer
	peerGroupMap map[string]*peerGroup
	globalRib    *table.TableManager
	rsRib        *table.TableManager
	roaManager   *roaManager
	shutdownWG   *sync.WaitGroup
	watcherMap   map[watchEventType][]*watcher
	zclient      *zebraClient
	bmpManager   *bmpClientManager
	mrtManager   *mrtManager
	roaTable     *table.ROATable
	uuidMap      map[string]uuid.UUID
	logger       log.Logger
}

func NewBgpServer(opt ...ServerOption) *BgpServer {
	opts := options{}
	for _, o := range opt {
		o(&opts)
	}
	logger := opts.logger
	if logger == nil {
		logger = log.NewDefaultLogger()
	}
	roaTable := table.NewROATable(logger)

	s := &BgpServer{
		neighborMap:  make(map[string]*peer),
		peerGroupMap: make(map[string]*peerGroup),
		policy:       table.NewRoutingPolicy(logger),
		mgmtCh:       make(chan *mgmtOp, 1),
		watcherMap:   make(map[watchEventType][]*watcher),
		uuidMap:      make(map[string]uuid.UUID),
		roaManager:   newROAManager(roaTable, logger),
		roaTable:     roaTable,
		logger:       logger,
	}
	s.bmpManager = newBmpClientManager(s)
	s.mrtManager = newMrtManager(s)
	if len(opts.grpcAddress) != 0 {
		grpc.EnableTracing = false
		s.apiServer = newAPIserver(s, grpc.NewServer(opts.grpcOption...), opts.grpcAddress)
		go func() {
			if err := s.apiServer.serve(); err != nil {
				logger.Fatal("failed to listen grpc port",
					log.Fields{"Err": err})
			}
		}()

	}
	return s
}

func (s *BgpServer) Stop() {
	s.StopBgp(context.Background(), &api.StopBgpRequest{})

	if s.apiServer != nil {
		s.apiServer.grpcServer.Stop()
	}
}

func (s *BgpServer) addIncoming(ch *channels.InfiniteChannel) {
	s.incomings = append(s.incomings, ch)
}

func (s *BgpServer) delIncoming(ch *channels.InfiniteChannel) {
	for i, c := range s.incomings {
		if c == ch {
			s.incomings = append(s.incomings[:i], s.incomings[i+1:]...)
			return
		}
	}
}

func (s *BgpServer) listListeners(addr string) []*net.TCPListener {
	list := make([]*net.TCPListener, 0, len(s.listeners))
	rhs := net.ParseIP(addr).To4() != nil
	for _, l := range s.listeners {
		host, _, _ := net.SplitHostPort(l.l.Addr().String())
		lhs := net.ParseIP(host).To4() != nil
		if lhs == rhs {
			list = append(list, l.l)
		}
	}
	return list
}

func (s *BgpServer) active() error {
	if s.bgpConfig.Global.Config.As == 0 {
		return fmt.Errorf("bgp server hasn't started yet")
	}
	return nil
}

type mgmtOp struct {
	f           func() error
	errCh       chan error
	checkActive bool // check BGP global setting is configured before calling f()
}

func (s *BgpServer) handleMGMTOp(op *mgmtOp) {
	if op.checkActive {
		if err := s.active(); err != nil {
			op.errCh <- err
			return
		}
	}
	op.errCh <- op.f()
}

func (s *BgpServer) mgmtOperation(f func() error, checkActive bool) (err error) {
	ch := make(chan error)
	defer func() { err = <-ch }()
	s.mgmtCh <- &mgmtOp{
		f:           f,
		errCh:       ch,
		checkActive: checkActive,
	}
	return
}

func (s *BgpServer) passConnToPeer(conn *net.TCPConn) {
	host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	ipaddr, _ := net.ResolveIPAddr("ip", host)
	remoteAddr := ipaddr.String()
	peer, found := s.neighborMap[remoteAddr]
	if found {
		peer.fsm.lock.RLock()
		adminStateNotUp := peer.fsm.adminState != adminStateUp
		peer.fsm.lock.RUnlock()
		if adminStateNotUp {
			peer.fsm.lock.RLock()
			s.logger.Debug("New connection for non admin-state-up peer",
				log.Fields{
					"Topic":       "Peer",
					"Remote Addr": remoteAddr,
					"Admin State": peer.fsm.adminState,
				})
			peer.fsm.lock.RUnlock()
			conn.Close()
			return
		}
		peer.fsm.lock.RLock()
		localAddr := peer.fsm.pConf.Transport.Config.LocalAddress
		bindInterface := peer.fsm.pConf.Transport.Config.BindInterface
		peer.fsm.lock.RUnlock()
		localAddrValid := func(laddr string) bool {
			if laddr == "0.0.0.0" || laddr == "::" {
				return true
			}
			l := conn.LocalAddr()
			if l == nil {
				// already closed
				return false
			}

			host, _, _ := net.SplitHostPort(l.String())
			if host != laddr && bindInterface == "" {
				s.logger.Info("Mismatched local address",
					log.Fields{
						"Topic":           "Peer",
						"Key":             remoteAddr,
						"Configured addr": laddr,
						"Addr":            host,
						"BindInterface":   bindInterface})
				return false
			}
			return true
		}(localAddr)

		if !localAddrValid {
			conn.Close()
			return
		}

		s.logger.Debug("Accepted a new passive connection",
			log.Fields{
				"Topic": "Peer",
				"Key":   remoteAddr})
		peer.PassConn(conn)
	} else if pg := s.matchLongestDynamicNeighborPrefix(remoteAddr); pg != nil {
		s.logger.Debug("Accepted a new dynamic neighbor",
			log.Fields{
				"Topic": "Peer",
				"Key":   remoteAddr})
		rib := s.globalRib
		if pg.Conf.RouteServer.Config.RouteServerClient {
			rib = s.rsRib
		}
		peer := newDynamicPeer(&s.bgpConfig.Global, remoteAddr, pg.Conf, rib, s.policy, s.logger)
		if peer == nil {
			s.logger.Info("Can't create new Dynamic Peer",
				log.Fields{
					"Topic": "Peer",
					"Key":   remoteAddr})
			conn.Close()
			return
		}
		s.addIncoming(peer.fsm.incomingCh)
		peer.fsm.lock.RLock()
		policy := peer.fsm.pConf.ApplyPolicy
		peer.fsm.lock.RUnlock()
		s.policy.SetPeerPolicy(peer.ID(), policy)
		s.neighborMap[remoteAddr] = peer
		peer.startFSMHandler()
		s.broadcastPeerState(peer, bgp.BGP_FSM_ACTIVE, nil)
		peer.PassConn(conn)
	} else {
		s.logger.Info("Can't find configuration for a new passive connection",
			log.Fields{
				"Topic": "Peer",
				"Key":   remoteAddr})
		conn.Close()
	}
}

const firstPeerCaseIndex = 3

func (s *BgpServer) Serve() {
	s.listeners = make([]*tcpListener, 0, 2)

	handlefsmMsg := func(e *fsmMsg) {
		fsm := e.fsm
		if fsm.h.ctx.Err() != nil {
			// canceled
			addr := fsm.pConf.State.NeighborAddress
			state := fsm.state

			fsm.h.wg.Wait()

			s.logger.Debug("freed fsm.h",
				log.Fields{
					"Topic": "Peer",
					"Key":   addr,
					"State": state})

			if fsm.state == bgp.BGP_FSM_ESTABLISHED {
				s.notifyWatcher(watchEventTypePeerState, &watchEventPeer{
					PeerAS:      fsm.peerInfo.AS,
					PeerAddress: fsm.peerInfo.Address,
					PeerID:      fsm.peerInfo.ID,
					State:       bgp.BGP_FSM_IDLE,
					Timestamp:   time.Now(),
					StateReason: &fsmStateReason{
						Type: fsmDeConfigured,
					},
				})
			}

			cleanInfiniteChannel(fsm.outgoingCh)
			cleanInfiniteChannel(fsm.incomingCh)
			s.delIncoming(fsm.incomingCh)
			if s.shutdownWG != nil && len(s.incomings) == 0 {
				s.shutdownWG.Done()
			}
			return
		}

		peer, found := s.neighborMap[e.MsgSrc]
		if !found {
			s.logger.Warn("Can't find the neighbor",
				log.Fields{
					"Topic": "Peer",
					"Key":   e.MsgSrc})
			return
		}
		s.handleFSMMessage(peer, e)
	}

	for {
		cases := make([]reflect.SelectCase, firstPeerCaseIndex+len(s.incomings))
		cases[0] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(s.mgmtCh),
		}
		cases[1] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(s.acceptCh),
		}
		cases[2] = reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(s.roaManager.ReceiveROA()),
		}
		for i := firstPeerCaseIndex; i < len(cases); i++ {
			cases[i] = reflect.SelectCase{
				Dir:  reflect.SelectRecv,
				Chan: reflect.ValueOf(s.incomings[i-firstPeerCaseIndex].Out()),
			}
		}

		chosen, value, ok := reflect.Select(cases)
		switch chosen {
		case 0:
			op := value.Interface().(*mgmtOp)
			s.handleMGMTOp(op)
		case 1:
			conn := value.Interface().(*net.TCPConn)
			s.passConnToPeer(conn)
		case 2:
			ev := value.Interface().(*roaEvent)
			s.roaManager.HandleROAEvent(ev)
		default:
			// in the case of dynamic peer, handleFSMMessage closed incoming channel so
			// nil fsmMsg can happen here.
			if ok {
				e := value.Interface().(*fsmMsg)
				handlefsmMsg(e)
			}
		}
	}
}

func (s *BgpServer) matchLongestDynamicNeighborPrefix(a string) *peerGroup {
	ipAddr := net.ParseIP(a)
	longestMask := net.CIDRMask(0, 32).String()
	var longestPG *peerGroup
	for _, pg := range s.peerGroupMap {
		for _, d := range pg.dynamicNeighbors {
			_, netAddr, _ := net.ParseCIDR(d.Config.Prefix)
			if netAddr.Contains(ipAddr) {
				if netAddr.Mask.String() > longestMask ||
					(netAddr.Mask.String() == longestMask && longestMask == net.CIDRMask(0, 32).String()) {
					longestMask = netAddr.Mask.String()
					longestPG = pg
				}
			}
		}
	}
	return longestPG
}

func sendfsmOutgoingMsg(peer *peer, paths []*table.Path, notification *bgp.BGPMessage, stayIdle bool) {
	peer.fsm.outgoingCh.In() <- &fsmOutgoingMsg{
		Paths:        paths,
		Notification: notification,
		StayIdle:     stayIdle,
	}
}

func isASLoop(peer *peer, path *table.Path) bool {
	for _, as := range path.GetAsList() {
		if as == peer.AS() {
			return true
		}
	}
	return false
}

func filterpath(peer *peer, path, old *table.Path) *table.Path {
	if path == nil {
		return nil
	}

	peer.fsm.lock.RLock()
	_, ok := peer.fsm.rfMap[path.GetRouteFamily()]
	peer.fsm.lock.RUnlock()
	if !ok {
		return nil
	}

	//RFC4684 Constrained Route Distribution
	peer.fsm.lock.RLock()
	_, y := peer.fsm.rfMap[bgp.RF_RTC_UC]
	peer.fsm.lock.RUnlock()
	if y && path.GetRouteFamily() != bgp.RF_RTC_UC {
		ignore := true
		for _, ext := range path.GetExtCommunities() {
			for _, p := range peer.adjRibIn.PathList([]bgp.RouteFamily{bgp.RF_RTC_UC}, true) {
				rt := p.GetNlri().(*bgp.RouteTargetMembershipNLRI).RouteTarget
				// Note: nil RT means the default route target
				if rt == nil || ext.String() == rt.String() {
					ignore = false
					break
				}
			}
			if !ignore {
				break
			}
		}
		if ignore {
			peer.fsm.logger.Debug("Filtered by Route Target Constraint, ignore",
				log.Fields{
					"Topic": "Peer",
					"Key":   peer.ID(),
					"Data":  path})
			return nil
		}
	}

	//iBGP handling
	if peer.isIBGPPeer() {
		ignore := false
		if !path.IsLocal() {
			ignore = true
			info := path.GetSource()
			//if the path comes from eBGP peer
			if info.AS != peer.AS() {
				ignore = false
			}
			if info.RouteReflectorClient {
				ignore = false
			}
			if peer.isRouteReflectorClient() {
				// RFC4456 8. Avoiding Routing Information Loops
				// If the local CLUSTER_ID is found in the CLUSTER_LIST,
				// the advertisement received SHOULD be ignored.
				for _, clusterID := range path.GetClusterList() {
					peer.fsm.lock.RLock()
					rrClusterID := peer.fsm.peerInfo.RouteReflectorClusterID
					peer.fsm.lock.RUnlock()
					if clusterID.Equal(rrClusterID) {
						peer.fsm.logger.Debug("cluster list path attribute has local cluster id, ignore",
							log.Fields{
								"Topic":     "Peer",
								"Key":       peer.ID(),
								"ClusterID": clusterID,
								"Data":      path})
						return nil
					}
				}
				ignore = false
			}
		}

		if ignore {
			if !path.IsWithdraw && old != nil {
				oldSource := old.GetSource()
				if old.IsLocal() || oldSource.Address.String() != peer.ID() && oldSource.AS != peer.AS() {
					// In this case, we suppose this peer has the same prefix
					// received from another iBGP peer.
					// So we withdraw the old best which was injected locally
					// (from CLI or gRPC for example) in order to avoid the
					// old best left on peers.
					// Also, we withdraw the eBGP route which is the old best.
					// When we got the new best from iBGP, we don't advertise
					// the new best and need to withdraw the old best.
					return old.Clone(true)
				}
			}
			peer.fsm.logger.Debug("From same AS, ignore",
				log.Fields{
					"Topic": "Peer",
					"Key":   peer.ID(),
					"Path":  path})
			return nil
		}
	}

	if path = peer.filterPathFromSourcePeer(path, old); path == nil {
		return nil
	}

	if !peer.isRouteServerClient() && isASLoop(peer, path) && !path.IsLocal() {
		return nil
	}
	return path
}

func (s *BgpServer) prePolicyFilterpath(peer *peer, path, old *table.Path) (*table.Path, *table.PolicyOptions, bool) {
	// Special handling for RTM NLRI.
	if path != nil && path.GetRouteFamily() == bgp.RF_RTC_UC && !path.IsWithdraw {
		// If the given "path" is locally generated and the same with "old", we
		// assumes "path" was already sent before. This assumption avoids the
		// infinite UPDATE loop between Route Reflector and its clients.
		if path.IsLocal() && path.Equal(old) {
			peer.fsm.lock.RLock()
			s.logger.Debug("given rtm nlri is already sent, skipping to advertise",
				log.Fields{
					"Topic": "Peer",
					"Key":   peer.fsm.pConf.State.NeighborAddress,
					"Path":  path})
			peer.fsm.lock.RUnlock()
			return nil, nil, true
		}

		if old != nil && old.IsLocal() {
			// We assumes VRF with the specific RT is deleted.
			path = old.Clone(true)
		} else if peer.isRouteReflectorClient() {
			// We need to send the path even if the peer is originator of the
			// path in order to signal that the client should distribute route
			// with the given RT.
		} else {
			// We send a path even if it is not the best path. See comments in
			// (*Destination) GetChanges().
			dst := peer.localRib.GetDestination(path)
			path = nil
			for _, p := range dst.GetKnownPathList(peer.TableID(), peer.AS()) {
				srcPeer := p.GetSource()
				if peer.ID() != srcPeer.Address.String() {
					if srcPeer.RouteReflectorClient {
						// The path from a RR client is preferred than others
						// for the case that RR and non RR client peering
						// (e.g., peering of different RR clusters).
						path = p
						break
					} else if path == nil {
						path = p
					}
				}
			}
		}
	}

	// only allow vpnv4 and vpnv6 paths to be advertised to VRFed neighbors.
	// also check we can import this path using table.CanImportToVrf()
	// if we can, make it local path by calling (*Path).ToLocal()
	peer.fsm.lock.RLock()
	peerVrf := peer.fsm.pConf.Config.Vrf
	peer.fsm.lock.RUnlock()
	if path != nil && peerVrf != "" {
		if f := path.GetRouteFamily(); f != bgp.RF_IPv4_VPN && f != bgp.RF_IPv6_VPN && f != bgp.RF_FS_IPv4_VPN && f != bgp.RF_FS_IPv6_VPN {
			return nil, nil, true
		}
		vrf := peer.localRib.Vrfs[peerVrf]
		if table.CanImportToVrf(vrf, path) {
			path = path.ToLocal()
		} else {
			return nil, nil, true
		}
	}

	// replace-peer-as handling
	peer.fsm.lock.RLock()
	if path != nil && !path.IsWithdraw && peer.fsm.pConf.AsPathOptions.State.ReplacePeerAs {
		path = path.ReplaceAS(peer.fsm.pConf.Config.LocalAs, peer.fsm.pConf.Config.PeerAs)
	}
	peer.fsm.lock.RUnlock()

	if path = filterpath(peer, path, old); path == nil {
		return nil, nil, true
	}

	peer.fsm.lock.RLock()
	options := &table.PolicyOptions{
		Info:       peer.fsm.peerInfo,
		OldNextHop: path.GetNexthop(),
	}
	path = table.UpdatePathAttrs(peer.fsm.logger, peer.fsm.gConf, peer.fsm.pConf, peer.fsm.peerInfo, path)
	peer.fsm.lock.RUnlock()

	return path, options, false
}

func (s *BgpServer) postFilterpath(peer *peer, path *table.Path) *table.Path {
	// draft-uttaro-idr-bgp-persistence-02
	// 4.3.  Processing LLGR_STALE Routes
	//
	// The route SHOULD NOT be advertised to any neighbor from which the
	// Long-lived Graceful Restart Capability has not been received.  The
	// exception is described in the Optional Partial Deployment
	// Procedure section (Section 4.7).  Note that this requirement
	// implies that such routes should be withdrawn from any such neighbor.
	if path != nil && !path.IsWithdraw && !peer.isLLGREnabledFamily(path.GetRouteFamily()) && path.IsLLGRStale() {
		// we send unnecessary withdrawn even if we didn't
		// sent the route.
		path = path.Clone(true)
	}

	// remove local-pref attribute
	// we should do this after applying export policy since policy may
	// set local-preference
	if path != nil && !peer.isIBGPPeer() && !peer.isRouteServerClient() {
		path.RemoveLocalPref()
	}
	return path
}

func (s *BgpServer) filterpath(peer *peer, path, old *table.Path) *table.Path {
	path, options, stop := s.prePolicyFilterpath(peer, path, old)
	if stop {
		return path
	}
	options.Validate = s.roaTable.Validate
	path = peer.policy.ApplyPolicy(peer.TableID(), table.POLICY_DIRECTION_EXPORT, path, options)
	// When 'path' is filtered (path == nil), check 'old' has been sent to this peer.
	// If it has, send withdrawal to the peer.
	if path == nil && old != nil {
		o := peer.policy.ApplyPolicy(peer.TableID(), table.POLICY_DIRECTION_EXPORT, old, options)
		if o != nil {
			path = old.Clone(true)
		}
	}

	return s.postFilterpath(peer, path)
}

func clonePathList(pathList []*table.Path) []*table.Path {
	l := make([]*table.Path, 0, len(pathList))
	for _, p := range pathList {
		if p != nil {
			l = append(l, p.Clone(p.IsWithdraw))
		}
	}
	return l
}

func (s *BgpServer) setPathVrfIdMap(paths []*table.Path, m map[uint32]bool) {
	for _, p := range paths {
		switch p.GetRouteFamily() {
		case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
			for _, vrf := range s.globalRib.Vrfs {
				if vrf.Id != 0 && table.CanImportToVrf(vrf, p) {
					m[uint32(vrf.Id)] = true
				}
			}
		default:
			m[zebra.DefaultVrf] = true
		}
	}
}

// Note: the destination would be the same for all the paths passed here
// The wather (only zapi) needs a unique list of vrf IDs
func (s *BgpServer) notifyBestWatcher(best []*table.Path, multipath [][]*table.Path) {
	if table.SelectionOptions.DisableBestPathSelection {
		// Note: If best path selection disabled, no best path to notify.
		return
	}
	m := make(map[uint32]bool)
	clonedM := make([][]*table.Path, len(multipath))
	for i, pathList := range multipath {
		clonedM[i] = clonePathList(pathList)
		if table.UseMultiplePaths.Enabled {
			s.setPathVrfIdMap(clonedM[i], m)
		}
	}
	clonedB := clonePathList(best)
	if !table.UseMultiplePaths.Enabled {
		s.setPathVrfIdMap(clonedB, m)
	}
	w := &watchEventBestPath{PathList: clonedB, MultiPathList: clonedM}
	if len(m) > 0 {
		w.Vrf = m
	}
	s.notifyWatcher(watchEventTypeBestPath, w)
}

func (s *BgpServer) toConfig(peer *peer, getAdvertised bool) *config.Neighbor {
	// create copy which can be access to without mutex
	peer.fsm.lock.RLock()
	conf := *peer.fsm.pConf
	peerAfiSafis := peer.fsm.pConf.AfiSafis
	peerCapMap := peer.fsm.capMap
	peer.fsm.lock.RUnlock()

	conf.AfiSafis = make([]config.AfiSafi, len(peerAfiSafis))
	for i, af := range peerAfiSafis {
		conf.AfiSafis[i] = af
		conf.AfiSafis[i].AddPaths.State.Receive = peer.isAddPathReceiveEnabled(af.State.Family)
		if peer.isAddPathSendEnabled(af.State.Family) {
			conf.AfiSafis[i].AddPaths.State.SendMax = af.AddPaths.State.SendMax
		} else {
			conf.AfiSafis[i].AddPaths.State.SendMax = 0
		}
	}

	remoteCap := make([]bgp.ParameterCapabilityInterface, 0, len(peerCapMap))
	for _, caps := range peerCapMap {
		for _, m := range caps {
			// need to copy all values here
			buf, _ := m.Serialize()
			c, _ := bgp.DecodeCapability(buf)
			remoteCap = append(remoteCap, c)
		}
	}

	conf.State.RemoteCapabilityList = remoteCap

	peer.fsm.lock.RLock()
	conf.State.LocalCapabilityList = capabilitiesFromConfig(peer.fsm.pConf)
	conf.State.SessionState = config.IntToSessionStateMap[int(peer.fsm.state)]
	conf.State.AdminState = config.IntToAdminStateMap[int(peer.fsm.adminState)]
	state := peer.fsm.state
	peer.fsm.lock.RUnlock()

	if state == bgp.BGP_FSM_ESTABLISHED {
		peer.fsm.lock.RLock()
		conf.Transport.State.LocalAddress, conf.Transport.State.LocalPort = peer.fsm.LocalHostPort()
		_, conf.Transport.State.RemotePort = peer.fsm.RemoteHostPort()
		buf, _ := peer.fsm.recvOpen.Serialize()
		// need to copy all values here
		conf.State.ReceivedOpenMessage, _ = bgp.ParseBGPMessage(buf)
		conf.State.RemoteRouterId = peer.fsm.peerInfo.ID.To4().String()
		peer.fsm.lock.RUnlock()
	}
	return &conf
}

func (s *BgpServer) notifyPrePolicyUpdateWatcher(peer *peer, pathList []*table.Path, msg *bgp.BGPMessage, timestamp time.Time, payload []byte) {
	if !s.isWatched(watchEventTypePreUpdate) || peer == nil {
		return
	}

	cloned := clonePathList(pathList)
	if len(cloned) == 0 {
		return
	}
	n := s.toConfig(peer, false)
	peer.fsm.lock.RLock()
	_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
	l, _ := peer.fsm.LocalHostPort()
	ev := &watchEventUpdate{
		Message:      msg,
		PeerAS:       peer.fsm.peerInfo.AS,
		LocalAS:      peer.fsm.peerInfo.LocalAS,
		PeerAddress:  peer.fsm.peerInfo.Address,
		LocalAddress: net.ParseIP(l),
		PeerID:       peer.fsm.peerInfo.ID,
		FourBytesAs:  y,
		Timestamp:    timestamp,
		Payload:      payload,
		PostPolicy:   false,
		PathList:     cloned,
		Neighbor:     n,
	}
	peer.fsm.lock.RUnlock()
	s.notifyWatcher(watchEventTypePreUpdate, ev)
}

func (s *BgpServer) notifyPostPolicyUpdateWatcher(peer *peer, pathList []*table.Path) {
	if !s.isWatched(watchEventTypePostUpdate) || peer == nil {
		return
	}

	cloned := clonePathList(pathList)
	if len(cloned) == 0 {
		return
	}
	n := s.toConfig(peer, false)
	peer.fsm.lock.RLock()
	_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
	l, _ := peer.fsm.LocalHostPort()
	ev := &watchEventUpdate{
		PeerAS:       peer.fsm.peerInfo.AS,
		LocalAS:      peer.fsm.peerInfo.LocalAS,
		PeerAddress:  peer.fsm.peerInfo.Address,
		LocalAddress: net.ParseIP(l),
		PeerID:       peer.fsm.peerInfo.ID,
		FourBytesAs:  y,
		Timestamp:    cloned[0].GetTimestamp(),
		PostPolicy:   true,
		PathList:     cloned,
		Neighbor:     n,
	}
	peer.fsm.lock.RUnlock()
	s.notifyWatcher(watchEventTypePostUpdate, ev)
}

func newWatchEventPeer(peer *peer, m *fsmMsg, oldState bgp.FSMState, t PeerEventType) *watchEventPeer {
	var laddr string
	var rport, lport uint16
	if peer.fsm.conn != nil {
		_, rport = peer.fsm.RemoteHostPort()
		laddr, lport = peer.fsm.LocalHostPort()
	}
	sentOpen := buildopen(peer.fsm.gConf, peer.fsm.pConf)
	peer.fsm.lock.RLock()
	recvOpen := peer.fsm.recvOpen
	e := &watchEventPeer{
		Type:          t,
		PeerAS:        peer.fsm.peerInfo.AS,
		LocalAS:       peer.fsm.peerInfo.LocalAS,
		PeerAddress:   peer.fsm.peerInfo.Address,
		LocalAddress:  net.ParseIP(laddr),
		PeerPort:      rport,
		LocalPort:     lport,
		PeerID:        peer.fsm.peerInfo.ID,
		SentOpen:      sentOpen,
		RecvOpen:      recvOpen,
		State:         peer.fsm.state,
		OldState:      oldState,
		AdminState:    peer.fsm.adminState,
		Timestamp:     time.Now(),
		PeerInterface: peer.fsm.pConf.Config.NeighborInterface,
	}
	peer.fsm.lock.RUnlock()

	if m != nil {
		e.StateReason = m.StateReason
	}
	return e
}

func (s *BgpServer) broadcastPeerState(peer *peer, oldState bgp.FSMState, e *fsmMsg) {
	s.notifyWatcher(watchEventTypePeerState, newWatchEventPeer(peer, e, oldState, PEER_EVENT_STATE))
}

func (s *BgpServer) notifyMessageWatcher(peer *peer, timestamp time.Time, msg *bgp.BGPMessage, isSent bool) {
	// validation should be done in the caller of this function
	peer.fsm.lock.RLock()
	_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
	l, _ := peer.fsm.LocalHostPort()
	ev := &watchEventMessage{
		Message:      msg,
		PeerAS:       peer.fsm.peerInfo.AS,
		LocalAS:      peer.fsm.peerInfo.LocalAS,
		PeerAddress:  peer.fsm.peerInfo.Address,
		LocalAddress: net.ParseIP(l),
		PeerID:       peer.fsm.peerInfo.ID,
		FourBytesAs:  y,
		Timestamp:    timestamp,
		IsSent:       isSent,
	}
	peer.fsm.lock.RUnlock()
	if !isSent {
		s.notifyWatcher(watchEventTypeRecvMsg, ev)
	}
}

func (s *BgpServer) notifyRecvMessageWatcher(peer *peer, timestamp time.Time, msg *bgp.BGPMessage) {
	if peer == nil || !s.isWatched(watchEventTypeRecvMsg) {
		return
	}
	s.notifyMessageWatcher(peer, timestamp, msg, false)
}

func (s *BgpServer) getPossibleBest(peer *peer, family bgp.RouteFamily) []*table.Path {
	if peer.isAddPathSendEnabled(family) {
		return peer.localRib.GetPathList(peer.TableID(), peer.AS(), []bgp.RouteFamily{family})
	}
	return peer.localRib.GetBestPathList(peer.TableID(), peer.AS(), []bgp.RouteFamily{family})
}

func (s *BgpServer) getBestFromLocal(peer *peer, rfList []bgp.RouteFamily) ([]*table.Path, []*table.Path) {
	pathList := []*table.Path{}
	filtered := []*table.Path{}

	if peer.isSecondaryRouteEnabled() {
		for _, family := range peer.toGlobalFamilies(rfList) {
			dsts := s.rsRib.Tables[family].GetDestinations()
			dl := make([]*table.Update, 0, len(dsts))
			for _, d := range dsts {
				l := d.GetAllKnownPathList()
				pl := make([]*table.Path, len(l))
				copy(pl, l)
				u := &table.Update{
					KnownPathList: pl,
				}
				dl = append(dl, u)
			}
			pathList = append(pathList, s.sendSecondaryRoutes(peer, nil, dl)...)
		}
		return pathList, filtered
	}

	for _, family := range peer.toGlobalFamilies(rfList) {
		for _, path := range s.getPossibleBest(peer, family) {
			if p := s.filterpath(peer, path, nil); p != nil {
				pathList = append(pathList, p)
			} else {
				filtered = append(filtered, path)
			}
		}
	}
	if peer.isGracefulRestartEnabled() {
		for _, family := range rfList {
			pathList = append(pathList, table.NewEOR(family))
		}
	}
	return pathList, filtered
}

func needToAdvertise(peer *peer) bool {
	peer.fsm.lock.RLock()
	notEstablished := peer.fsm.state != bgp.BGP_FSM_ESTABLISHED
	localRestarting := peer.fsm.pConf.GracefulRestart.State.LocalRestarting
	peer.fsm.lock.RUnlock()
	if notEstablished {
		return false
	}
	if localRestarting {
		peer.fsm.lock.RLock()
		peer.fsm.logger.Debug("now syncing, suppress sending updates",
			log.Fields{
				"Topic": "Peer",
				"Key":   peer.fsm.pConf.State.NeighborAddress})
		peer.fsm.lock.RUnlock()
		return false
	}
	return true
}

func (s *BgpServer) sendSecondaryRoutes(peer *peer, newPath *table.Path, dsts []*table.Update) []*table.Path {
	if !needToAdvertise(peer) {
		return nil
	}
	pl := make([]*table.Path, 0, len(dsts))

	f := func(path, old *table.Path) *table.Path {
		path, options, stop := s.prePolicyFilterpath(peer, path, old)
		if stop {
			return nil
		}
		options.Validate = s.roaTable.Validate
		path = peer.policy.ApplyPolicy(peer.TableID(), table.POLICY_DIRECTION_EXPORT, path, options)
		if path != nil {
			return s.postFilterpath(peer, path)
		}
		return nil
	}

	for _, dst := range dsts {
		old := func() *table.Path {
			for _, old := range dst.OldKnownPathList {
				o := f(old, nil)
				if o != nil {
					return o
				}
			}
			return nil
		}()
		path := func() *table.Path {
			for _, known := range dst.KnownPathList {
				path := f(known, old)
				if path != nil {
					return path
				}
			}
			return nil
		}()
		if path != nil {
			pl = append(pl, path)
		} else if old != nil {
			pl = append(pl, old.Clone(true))
		}
	}
	return pl
}

func (s *BgpServer) processOutgoingPaths(peer *peer, paths, olds []*table.Path) []*table.Path {
	if !needToAdvertise(peer) {
		return nil
	}

	outgoing := make([]*table.Path, 0, len(paths))

	for idx, path := range paths {
		var old *table.Path
		if olds != nil {
			old = olds[idx]
		}
		if p := s.filterpath(peer, path, old); p != nil {
			outgoing = append(outgoing, p)
		}
	}
	return outgoing
}

func (s *BgpServer) handleRouteRefresh(peer *peer, e *fsmMsg) []*table.Path {
	m := e.MsgData.(*bgp.BGPMessage)
	rr := m.Body.(*bgp.BGPRouteRefresh)
	rf := bgp.AfiSafiToRouteFamily(rr.AFI, rr.SAFI)

	peer.fsm.lock.RLock()
	_, ok := peer.fsm.rfMap[rf]
	peer.fsm.lock.RUnlock()
	if !ok {
		s.logger.Warn("Route family isn't supported",
			log.Fields{
				"Topic":  "Peer",
				"Key":    peer.ID(),
				"Family": rf})
		return nil
	}

	peer.fsm.lock.RLock()
	_, ok = peer.fsm.capMap[bgp.BGP_CAP_ROUTE_REFRESH]
	peer.fsm.lock.RUnlock()
	if !ok {
		s.logger.Warn("ROUTE_REFRESH received but the capability wasn't advertised",
			log.Fields{
				"Topic": "Peer",
				"Key":   peer.ID()})
		return nil
	}
	rfList := []bgp.RouteFamily{rf}
	accepted, _ := s.getBestFromLocal(peer, rfList)
	return accepted
}

func (s *BgpServer) propagateUpdate(peer *peer, pathList []*table.Path) {
	rs := peer != nil && peer.isRouteServerClient()
	vrf := false
	if peer != nil {
		peer.fsm.lock.RLock()
		vrf = !rs && peer.fsm.pConf.Config.Vrf != ""
		peer.fsm.lock.RUnlock()
	}

	tableId := table.GLOBAL_RIB_NAME
	rib := s.globalRib
	if rs {
		tableId = peer.TableID()
		rib = s.rsRib
	}

	for _, path := range pathList {
		if vrf {
			peer.fsm.lock.RLock()
			peerVrf := peer.fsm.pConf.Config.Vrf
			peer.fsm.lock.RUnlock()
			path = path.ToGlobal(rib.Vrfs[peerVrf])
			if s.zclient != nil {
				s.zclient.pathVrfMap[path] = rib.Vrfs[peerVrf].Id
			}
		}

		policyOptions := &table.PolicyOptions{
			Validate: s.roaTable.Validate,
		}

		if !rs && peer != nil {
			peer.fsm.lock.RLock()
			policyOptions.Info = peer.fsm.peerInfo
			peer.fsm.lock.RUnlock()
		}

		if p := s.policy.ApplyPolicy(tableId, table.POLICY_DIRECTION_IMPORT, path, policyOptions); p != nil {
			path = p
		} else {
			path = path.Clone(true)
		}

		if !rs {
			s.notifyPostPolicyUpdateWatcher(peer, []*table.Path{path})

			// RFC4684 Constrained Route Distribution 6. Operation
			//
			// When a BGP speaker receives a BGP UPDATE that advertises or withdraws
			// a given Route Target membership NLRI, it should examine the RIB-OUTs
			// of VPN NLRIs and re-evaluate the advertisement status of routes that
			// match the Route Target in question.
			//
			// A BGP speaker should generate the minimum set of BGP VPN route
			// updates (advertisements and/or withdraws) necessary to transition
			// between the previous and current state of the route distribution
			// graph that is derived from Route Target membership information.
			if peer != nil && path != nil && path.GetRouteFamily() == bgp.RF_RTC_UC {
				rt := path.GetNlri().(*bgp.RouteTargetMembershipNLRI).RouteTarget
				fs := make([]bgp.RouteFamily, 0, len(peer.negotiatedRFList()))
				for _, f := range peer.negotiatedRFList() {
					if f != bgp.RF_RTC_UC {
						fs = append(fs, f)
					}
				}
				var candidates []*table.Path
				if path.IsWithdraw {
					// Note: The paths to be withdrawn are filtered because the
					// given RT on RTM NLRI is already removed from adj-RIB-in.
					_, candidates = s.getBestFromLocal(peer, fs)
				} else {
					// https://github.com/osrg/gobgp/issues/1777
					// Ignore duplicate Membership announcements
					membershipsForSource := s.globalRib.GetPathListWithSource(table.GLOBAL_RIB_NAME, []bgp.RouteFamily{bgp.RF_RTC_UC}, path.GetSource())
					found := false
					for _, membership := range membershipsForSource {
						if membership.GetNlri().(*bgp.RouteTargetMembershipNLRI).RouteTarget.String() == rt.String() {
							found = true
							break
						}
					}
					if !found {
						candidates = s.globalRib.GetBestPathList(peer.TableID(), 0, fs)
					}
				}
				paths := make([]*table.Path, 0, len(candidates))
				for _, p := range candidates {
					for _, ext := range p.GetExtCommunities() {
						if rt == nil || ext.String() == rt.String() {
							if path.IsWithdraw {
								p = p.Clone(true)
							}
							paths = append(paths, p)
							break
						}
					}
				}
				if path.IsWithdraw {
					// Skips filtering because the paths are already filtered
					// and the withdrawal does not need the path attributes.
				} else {
					paths = s.processOutgoingPaths(peer, paths, nil)
				}
				sendfsmOutgoingMsg(peer, paths, nil, false)
			}
		}

		if dsts := rib.Update(path); len(dsts) > 0 {
			s.propagateUpdateToNeighbors(peer, path, dsts, true)
		}
	}
}

func dstsToPaths(id string, as uint32, dsts []*table.Update) ([]*table.Path, []*table.Path, [][]*table.Path) {
	bestList := make([]*table.Path, 0, len(dsts))
	oldList := make([]*table.Path, 0, len(dsts))
	mpathList := make([][]*table.Path, 0, len(dsts))

	for _, dst := range dsts {
		best, old, mpath := dst.GetChanges(id, as, false)
		bestList = append(bestList, best)
		oldList = append(oldList, old)
		if mpath != nil {
			mpathList = append(mpathList, mpath)
		}
	}
	return bestList, oldList, mpathList
}

func (s *BgpServer) propagateUpdateToNeighbors(source *peer, newPath *table.Path, dsts []*table.Update, needOld bool) {
	if table.SelectionOptions.DisableBestPathSelection {
		return
	}
	var gBestList, gOldList, bestList, oldList []*table.Path
	var mpathList [][]*table.Path
	if source == nil || !source.isRouteServerClient() {
		gBestList, gOldList, mpathList = dstsToPaths(table.GLOBAL_RIB_NAME, 0, dsts)
		s.notifyBestWatcher(gBestList, mpathList)
	}
	family := newPath.GetRouteFamily()
	for _, targetPeer := range s.neighborMap {
		if (source == nil && targetPeer.isRouteServerClient()) || (source != nil && source.isRouteServerClient() != targetPeer.isRouteServerClient()) {
			continue
		}
		f := func() bgp.RouteFamily {
			targetPeer.fsm.lock.RLock()
			peerVrf := targetPeer.fsm.pConf.Config.Vrf
			targetPeer.fsm.lock.RUnlock()
			if peerVrf != "" {
				switch family {
				case bgp.RF_IPv4_VPN:
					return bgp.RF_IPv4_UC
				case bgp.RF_IPv6_VPN:
					return bgp.RF_IPv6_UC
				case bgp.RF_FS_IPv4_VPN:
					return bgp.RF_FS_IPv4_UC
				case bgp.RF_FS_IPv6_VPN:
					return bgp.RF_FS_IPv6_UC
				}
			}
			return family
		}()
		if targetPeer.isAddPathSendEnabled(f) {
			if newPath.IsWithdraw {
				bestList = func() []*table.Path {
					l := make([]*table.Path, 0, len(dsts))
					for _, d := range dsts {
						l = append(l, d.GetWithdrawnPath()...)
					}
					return l
				}()
			} else {
				bestList = []*table.Path{newPath}
				if newPath.GetRouteFamily() == bgp.RF_RTC_UC {
					// we assumes that new "path" nlri was already sent before. This assumption avoids the
					// infinite UPDATE loop between Route Reflector and its clients.
					for _, old := range dsts[0].OldKnownPathList {
						if old.IsLocal() {
							bestList = []*table.Path{}
							break
						}
					}
				}
			}
			oldList = nil
		} else if targetPeer.isRouteServerClient() {
			if targetPeer.isSecondaryRouteEnabled() {
				if paths := s.sendSecondaryRoutes(targetPeer, newPath, dsts); len(paths) > 0 {
					sendfsmOutgoingMsg(targetPeer, paths, nil, false)
				}
				continue
			}
			bestList, oldList, _ = dstsToPaths(targetPeer.TableID(), targetPeer.AS(), dsts)
		} else {
			bestList = gBestList
			oldList = gOldList
		}
		if !needOld {
			oldList = nil
		}
		if paths := s.processOutgoingPaths(targetPeer, bestList, oldList); len(paths) > 0 {
			sendfsmOutgoingMsg(targetPeer, paths, nil, false)
		}
	}
}

func (s *BgpServer) deleteDynamicNeighbor(peer *peer, oldState bgp.FSMState, e *fsmMsg) {
	peer.stopPeerRestarting()
	peer.fsm.lock.RLock()
	delete(s.neighborMap, peer.fsm.pConf.State.NeighborAddress)
	peer.fsm.lock.RUnlock()
	cleanInfiniteChannel(peer.fsm.outgoingCh)
	cleanInfiniteChannel(peer.fsm.incomingCh)
	s.delIncoming(peer.fsm.incomingCh)
	s.broadcastPeerState(peer, oldState, e)
}

func (s *BgpServer) handleFSMMessage(peer *peer, e *fsmMsg) {
	switch e.MsgType {
	case fsmMsgStateChange:
		nextState := e.MsgData.(bgp.FSMState)
		peer.fsm.lock.Lock()
		oldState := bgp.FSMState(peer.fsm.pConf.State.SessionState.ToInt())
		peer.fsm.pConf.State.SessionState = config.IntToSessionStateMap[int(nextState)]
		peer.fsm.lock.Unlock()

		peer.fsm.StateChange(nextState)

		peer.fsm.lock.RLock()
		nextStateIdle := peer.fsm.pConf.GracefulRestart.State.PeerRestarting && nextState == bgp.BGP_FSM_IDLE
		peer.fsm.lock.RUnlock()

		// PeerDown
		if oldState == bgp.BGP_FSM_ESTABLISHED {
			t := time.Now()
			peer.fsm.lock.Lock()
			if t.Sub(time.Unix(peer.fsm.pConf.Timers.State.Uptime, 0)) < flopThreshold {
				peer.fsm.pConf.State.Flops++
			}
			graceful := peer.fsm.reason.Type == fsmGracefulRestart
			peer.fsm.lock.Unlock()
			var drop []bgp.RouteFamily
			if graceful {
				peer.fsm.lock.Lock()
				peer.fsm.pConf.GracefulRestart.State.PeerRestarting = true
				peer.fsm.lock.Unlock()
				var p []bgp.RouteFamily
				p, drop = peer.forwardingPreservedFamilies()
				s.propagateUpdate(peer, peer.StaleAll(p))
			} else {
				drop = peer.configuredRFlist()
			}

			// Always clear EndOfRibReceived state on PeerDown
			peer.fsm.lock.Lock()
			for i := range peer.fsm.pConf.AfiSafis {
				peer.fsm.pConf.AfiSafis[i].MpGracefulRestart.State.EndOfRibReceived = false
			}
			peer.fsm.lock.Unlock()

			peer.prefixLimitWarned = make(map[bgp.RouteFamily]bool)
			s.propagateUpdate(peer, peer.DropAll(drop))

			peer.fsm.lock.Lock()
			if peer.fsm.pConf.Config.PeerAs == 0 {
				peer.fsm.pConf.State.PeerAs = 0
				peer.fsm.peerInfo.AS = 0
			}
			peer.fsm.lock.Unlock()

			if !graceful && peer.isDynamicNeighbor() {
				s.deleteDynamicNeighbor(peer, oldState, e)
				return
			}

		} else if nextStateIdle {
			peer.fsm.lock.RLock()
			longLivedEnabled := peer.fsm.pConf.GracefulRestart.State.LongLivedEnabled
			peer.fsm.lock.RUnlock()
			if longLivedEnabled {
				llgr, no_llgr := peer.llgrFamilies()

				s.propagateUpdate(peer, peer.DropAll(no_llgr))

				// attach LLGR_STALE community to paths in peer's adj-rib-in
				// paths with NO_LLGR are deleted
				pathList := peer.markLLGRStale(llgr)

				// calculate again
				// wheh path with LLGR_STALE chosen as best,
				// peer which doesn't support LLGR will drop the path
				// if it is in adj-rib-out, do withdrawal
				s.propagateUpdate(peer, pathList)

				for _, f := range llgr {
					endCh := make(chan struct{})
					peer.llgrEndChs = append(peer.llgrEndChs, endCh)
					go func(family bgp.RouteFamily, endCh chan struct{}) {
						t := peer.llgrRestartTime(family)
						timer := time.NewTimer(time.Second * time.Duration(t))

						s.logger.Info("LLGR restart timer started",
							log.Fields{
								"Topic":    "Peer",
								"Key":      peer.ID(),
								"Family":   family,
								"Duration": t})

						select {
						case <-timer.C:
							s.mgmtOperation(func() error {
								s.logger.Info("LLGR restart timer expired",
									log.Fields{
										"Topic":    "Peer",
										"Key":      peer.ID(),
										"Family":   family,
										"Duration": t})

								s.propagateUpdate(peer, peer.DropAll([]bgp.RouteFamily{family}))

								// when all llgr restart timer expired, stop PeerRestarting
								if peer.llgrRestartTimerExpired(family) {
									peer.stopPeerRestarting()
								}
								return nil
							}, false)
						case <-endCh:
							s.logger.Info("LLGR restart timer stopped",
								log.Fields{
									"Topic":    "Peer",
									"Key":      peer.ID(),
									"Family":   family,
									"Duration": t})
						}
					}(f, endCh)
				}
			} else {
				// RFC 4724 4.2
				// If the session does not get re-established within the "Restart Time"
				// that the peer advertised previously, the Receiving Speaker MUST
				// delete all the stale routes from the peer that it is retaining.
				peer.fsm.lock.Lock()
				peer.fsm.pConf.GracefulRestart.State.PeerRestarting = false
				peer.fsm.lock.Unlock()

				s.propagateUpdate(peer, peer.DropAll(peer.configuredRFlist()))

				if peer.isDynamicNeighbor() {
					s.deleteDynamicNeighbor(peer, oldState, e)
					return
				}
			}
		}

		cleanInfiniteChannel(peer.fsm.outgoingCh)
		peer.fsm.outgoingCh = channels.NewInfiniteChannel()
		if nextState == bgp.BGP_FSM_ESTABLISHED {
			// update for export policy
			laddr, _ := peer.fsm.LocalHostPort()
			// may include zone info
			peer.fsm.lock.Lock()
			peer.fsm.pConf.Transport.State.LocalAddress = laddr
			// exclude zone info
			ipaddr, _ := net.ResolveIPAddr("ip", laddr)
			peer.fsm.peerInfo.LocalAddress = ipaddr.IP
			neighborAddress := peer.fsm.pConf.State.NeighborAddress
			peer.fsm.lock.Unlock()
			deferralExpiredFunc := func(family bgp.RouteFamily) func() {
				return func() {
					s.mgmtOperation(func() error {
						s.softResetOut(neighborAddress, family, true)
						return nil
					}, false)
				}
			}
			peer.fsm.lock.RLock()
			notLocalRestarting := !peer.fsm.pConf.GracefulRestart.State.LocalRestarting
			peer.fsm.lock.RUnlock()
			if notLocalRestarting {
				// When graceful-restart cap (which means intention
				// of sending EOR) and route-target address family are negotiated,
				// send route-target NLRIs first, and wait to send others
				// till receiving EOR of route-target address family.
				// This prevents sending uninterested routes to peers.
				//
				// However, when the peer is graceful restarting, give up
				// waiting sending non-route-target NLRIs since the peer won't send
				// any routes (and EORs) before we send ours (or deferral-timer expires).
				var pathList []*table.Path
				peer.fsm.lock.RLock()
				_, y := peer.fsm.rfMap[bgp.RF_RTC_UC]
				c := peer.fsm.pConf.GetAfiSafi(bgp.RF_RTC_UC)
				notPeerRestarting := !peer.fsm.pConf.GracefulRestart.State.PeerRestarting
				peer.fsm.lock.RUnlock()
				if y && notPeerRestarting && c.RouteTargetMembership.Config.DeferralTime > 0 {
					pathList, _ = s.getBestFromLocal(peer, []bgp.RouteFamily{bgp.RF_RTC_UC})
					t := c.RouteTargetMembership.Config.DeferralTime
					for _, f := range peer.negotiatedRFList() {
						if f != bgp.RF_RTC_UC {
							time.AfterFunc(time.Second*time.Duration(t), deferralExpiredFunc(f))
						}
					}
				} else {
					pathList, _ = s.getBestFromLocal(peer, peer.negotiatedRFList())
				}

				if len(pathList) > 0 {
					sendfsmOutgoingMsg(peer, pathList, nil, false)
				}
			} else {
				// RFC 4724 4.1
				// Once the session between the Restarting Speaker and the Receiving
				// Speaker is re-established, ...snip... it MUST defer route
				// selection for an address family until it either (a) receives the
				// End-of-RIB marker from all its peers (excluding the ones with the
				// "Restart State" bit set in the received capability and excluding the
				// ones that do not advertise the graceful restart capability) or (b)
				// the Selection_Deferral_Timer referred to below has expired.
				allEnd := func() bool {
					for _, p := range s.neighborMap {
						if !p.recvedAllEOR() {
							return false
						}
					}
					return true
				}()
				if allEnd {
					for _, p := range s.neighborMap {
						p.fsm.lock.Lock()
						p.fsm.pConf.GracefulRestart.State.LocalRestarting = false
						p.fsm.lock.Unlock()
						if !p.isGracefulRestartEnabled() {
							continue
						}
						paths, _ := s.getBestFromLocal(p, p.configuredRFlist())
						if len(paths) > 0 {
							sendfsmOutgoingMsg(p, paths, nil, false)
						}
					}
					s.logger.Info("sync finished",
						log.Fields{
							"Topic": "Server",
							"Key":   peer.ID()})

				} else {
					peer.fsm.lock.RLock()
					deferral := peer.fsm.pConf.GracefulRestart.Config.DeferralTime
					peer.fsm.lock.RUnlock()
					s.logger.Debug("Now syncing, suppress sending updates. start deferral timer",
						log.Fields{
							"Topic":    "Server",
							"Key":      peer.ID(),
							"Duration": deferral})
					time.AfterFunc(time.Second*time.Duration(deferral), deferralExpiredFunc(bgp.RouteFamily(0)))
				}
			}
		} else {
			peer.fsm.lock.Lock()
			peer.fsm.pConf.Timers.State.Downtime = time.Now().Unix()
			peer.fsm.lock.Unlock()
		}
		// clear counter
		peer.fsm.lock.RLock()
		adminStateDown := peer.fsm.adminState == adminStateDown
		peer.fsm.lock.RUnlock()
		if adminStateDown {
			peer.fsm.lock.Lock()
			peer.fsm.pConf.State = config.NeighborState{}
			peer.fsm.pConf.State.NeighborAddress = peer.fsm.pConf.Config.NeighborAddress
			peer.fsm.pConf.State.PeerAs = peer.fsm.pConf.Config.PeerAs
			peer.fsm.pConf.Timers.State = config.TimersState{}
			peer.fsm.lock.Unlock()
		}
		peer.startFSMHandler()
		s.broadcastPeerState(peer, oldState, e)
	case fsmMsgRouteRefresh:
		peer.fsm.lock.RLock()
		notEstablished := peer.fsm.state != bgp.BGP_FSM_ESTABLISHED
		beforeUptime := e.timestamp.Unix() < peer.fsm.pConf.Timers.State.Uptime
		peer.fsm.lock.RUnlock()
		if notEstablished || beforeUptime {
			return
		}
		if paths := s.handleRouteRefresh(peer, e); len(paths) > 0 {
			sendfsmOutgoingMsg(peer, paths, nil, false)
			return
		}
	case fsmMsgBGPMessage:
		switch m := e.MsgData.(type) {
		case *bgp.MessageError:
			sendfsmOutgoingMsg(peer, nil, bgp.NewBGPNotificationMessage(m.TypeCode, m.SubTypeCode, m.Data), false)
			return
		case *bgp.BGPMessage:
			s.notifyRecvMessageWatcher(peer, e.timestamp, m)
			peer.fsm.lock.RLock()
			notEstablished := peer.fsm.state != bgp.BGP_FSM_ESTABLISHED
			beforeUptime := e.timestamp.Unix() < peer.fsm.pConf.Timers.State.Uptime
			peer.fsm.lock.RUnlock()
			if notEstablished || beforeUptime {
				return
			}
			pathList, eor, notification := peer.handleUpdate(e)
			if notification != nil {
				sendfsmOutgoingMsg(peer, nil, notification, true)
				return
			}
			if m.Header.Type == bgp.BGP_MSG_UPDATE {
				s.notifyPrePolicyUpdateWatcher(peer, pathList, m, e.timestamp, e.payload)
			}

			if len(pathList) > 0 {
				s.propagateUpdate(peer, pathList)
			}

			peer.fsm.lock.RLock()
			peerAfiSafis := peer.fsm.pConf.AfiSafis
			peer.fsm.lock.RUnlock()
			if len(eor) > 0 {
				rtc := false
				for _, f := range eor {
					if f == bgp.RF_RTC_UC {
						rtc = true
					}
					for i, a := range peerAfiSafis {
						if a.State.Family == f {
							peer.fsm.lock.Lock()
							peer.fsm.pConf.AfiSafis[i].MpGracefulRestart.State.EndOfRibReceived = true
							peer.fsm.lock.Unlock()
						}
					}
				}

				// RFC 4724 4.1
				// Once the session between the Restarting Speaker and the Receiving
				// Speaker is re-established, ...snip... it MUST defer route
				// selection for an address family until it either (a) receives the
				// End-of-RIB marker from all its peers (excluding the ones with the
				// "Restart State" bit set in the received capability and excluding the
				// ones that do not advertise the graceful restart capability) or ...snip...

				peer.fsm.lock.RLock()
				localRestarting := peer.fsm.pConf.GracefulRestart.State.LocalRestarting
				peer.fsm.lock.RUnlock()
				if localRestarting {
					allEnd := func() bool {
						for _, p := range s.neighborMap {
							if !p.recvedAllEOR() {
								return false
							}
						}
						return true
					}()
					if allEnd {
						for _, p := range s.neighborMap {
							p.fsm.lock.Lock()
							p.fsm.pConf.GracefulRestart.State.LocalRestarting = false
							p.fsm.lock.Unlock()
							if !p.isGracefulRestartEnabled() {
								continue
							}
							paths, _ := s.getBestFromLocal(p, p.negotiatedRFList())
							if len(paths) > 0 {
								sendfsmOutgoingMsg(p, paths, nil, false)
							}
						}
						s.logger.Info("sync finished",
							log.Fields{
								"Topic": "Server"})
					}

					// we don't delay non-route-target NLRIs when local-restarting
					rtc = false
				}
				peer.fsm.lock.RLock()
				peerRestarting := peer.fsm.pConf.GracefulRestart.State.PeerRestarting
				peer.fsm.lock.RUnlock()
				if peerRestarting {
					if peer.recvedAllEOR() {
						peer.stopPeerRestarting()
						pathList := peer.adjRibIn.DropStale(peer.configuredRFlist())
						peer.fsm.lock.RLock()
						s.logger.Debug("withdraw stale routes",
							log.Fields{
								"Topic":   "Peer",
								"Key":     peer.fsm.pConf.State.NeighborAddress,
								"Numbers": len(pathList)})
						peer.fsm.lock.RUnlock()
						s.propagateUpdate(peer, pathList)
					}

					// we don't delay non-route-target NLRIs when peer is restarting
					rtc = false
				}

				// received EOR of route-target address family
				// outbound filter is now ready, let's flash non-route-target NLRIs
				peer.fsm.lock.RLock()
				c := peer.fsm.pConf.GetAfiSafi(bgp.RF_RTC_UC)
				peer.fsm.lock.RUnlock()
				if rtc && c != nil && c.RouteTargetMembership.Config.DeferralTime > 0 {
					s.logger.Debug("received route-target eor. flash non-route-target NLRIs",
						log.Fields{
							"Topic": "Peer",
							"Key":   peer.ID()})
					families := make([]bgp.RouteFamily, 0, len(peer.negotiatedRFList()))
					for _, f := range peer.negotiatedRFList() {
						if f != bgp.RF_RTC_UC {
							families = append(families, f)
						}
					}
					if paths, _ := s.getBestFromLocal(peer, families); len(paths) > 0 {
						sendfsmOutgoingMsg(peer, paths, nil, false)
					}
				}
			}
		default:
			s.logger.Fatal("unknown msg type",
				log.Fields{
					"Topic": "Peer",
					"Key":   peer.fsm.pConf.State.NeighborAddress,
					"Data":  e.MsgData})
		}
	}
}

func (s *BgpServer) EnableZebra(ctx context.Context, r *api.EnableZebraRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		if s.zclient != nil {
			return fmt.Errorf("already connected to Zebra")
		}
		software := zebra.NewSoftware(uint8(r.Version), r.SoftwareName)
		for _, p := range r.RouteTypes {
			if _, err := zebra.RouteTypeFromString(p, uint8(r.Version), software); err != nil {
				return err
			}
		}

		protos := make([]string, 0, len(r.RouteTypes))
		for _, p := range r.RouteTypes {
			protos = append(protos, string(p))
		}
		var err error
		s.zclient, err = newZebraClient(s, r.Url, protos, uint8(r.Version), r.NexthopTriggerEnable, uint8(r.NexthopTriggerDelay), r.MplsLabelRangeSize, software)
		return err
	}, false)
}

func (s *BgpServer) AddBmp(ctx context.Context, r *api.AddBmpRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		_, ok := api.AddBmpRequest_MonitoringPolicy_name[int32(r.Policy)]
		if !ok {
			return fmt.Errorf("invalid bmp route monitoring policy: %v", r.Policy)
		}
		port := r.Port
		if port == 0 {
			port = bmp.BMP_DEFAULT_PORT
		}
		sysname := r.SysName
		if sysname == "" {
			sysname = "GoBGP"
		}
		sysDescr := r.SysDescr
		if sysDescr == "" {
			sysDescr = version.Version()
		}
		s.logger.Debug("add bmp server", log.Fields{"address": r.Address, "port": r.Port, "policy": r.Policy})
		return s.bmpManager.addServer(&config.BmpServerConfig{
			Address:               r.Address,
			Port:                  port,
			SysName:               sysname,
			SysDescr:              sysDescr,
			RouteMonitoringPolicy: config.IntToBmpRouteMonitoringPolicyTypeMap[int(r.Policy)],
			StatisticsTimeout:     uint16(r.StatisticsTimeout),
		})
	}, true)
}

func (s *BgpServer) DeleteBmp(ctx context.Context, r *api.DeleteBmpRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.bmpManager.deleteServer(&config.BmpServerConfig{
			Address: r.Address,
			Port:    r.Port,
		})
	}, true)
}

func (s *BgpServer) ListBmp(ctx context.Context, req *api.ListBmpRequest, fn func(*api.ListBmpResponse_BmpStation)) error {
	if req == nil {
		return fmt.Errorf("null request")
	}
	var stations []*api.ListBmpResponse_BmpStation
	err := s.mgmtOperation(func() error {
		for _, s := range s.bmpManager.clientMap {
			stations = append(stations, &api.ListBmpResponse_BmpStation{
				Conf: &api.ListBmpResponse_BmpStation_Conf{
					Address: s.c.Address,
					Port:    s.c.Port,
				},
				State: &api.ListBmpResponse_BmpStation_State{
					Uptime:   config.ProtoTimestamp(atomic.LoadInt64(&s.uptime)),
					Downtime: config.ProtoTimestamp(atomic.LoadInt64(&s.downtime)),
				},
			})
		}
		return nil
	}, false)
	if err == nil {
		for _, rsp := range stations {
			select {
			case <-ctx.Done():
				return nil
			default:
				fn(rsp)
			}
		}
	}
	return err
}

func (s *BgpServer) StopBgp(ctx context.Context, r *api.StopBgpRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	s.mgmtOperation(func() error {
		names := make([]string, 0, len(s.neighborMap))
		for k := range s.neighborMap {
			names = append(names, k)
		}

		if len(names) != 0 {
			s.shutdownWG = new(sync.WaitGroup)
			s.shutdownWG.Add(1)
		}
		for _, name := range names {
			if err := s.deleteNeighbor(&config.Neighbor{Config: config.NeighborConfig{
				NeighborAddress: name}}, bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED); err != nil {
				return err
			}
		}
		for _, l := range s.listeners {
			l.Close()
		}
		s.bgpConfig.Global = config.Global{}
		return nil
	}, false)

	if s.shutdownWG != nil {
		s.shutdownWG.Wait()
		s.shutdownWG = nil
	}
	return nil
}

func (s *BgpServer) SetPolicies(ctx context.Context, r *api.SetPoliciesRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	rp, err := newRoutingPolicyFromApiStruct(r)
	if err != nil {
		return err
	}

	getConfig := func(id string) (*config.ApplyPolicy, error) {
		f := func(id string, dir table.PolicyDirection) (config.DefaultPolicyType, []string, error) {
			rt, policies, err := s.policy.GetPolicyAssignment(id, dir)
			if err != nil {
				return config.DEFAULT_POLICY_TYPE_REJECT_ROUTE, nil, err
			}
			names := make([]string, 0, len(policies))
			for _, p := range policies {
				names = append(names, p.Name)
			}
			t := config.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE
			if rt == table.ROUTE_TYPE_REJECT {
				t = config.DEFAULT_POLICY_TYPE_REJECT_ROUTE
			}
			return t, names, nil
		}

		c := &config.ApplyPolicy{}
		rt, policies, err := f(id, table.POLICY_DIRECTION_IMPORT)
		if err != nil {
			return nil, err
		}
		c.Config.ImportPolicyList = policies
		c.Config.DefaultImportPolicy = rt
		rt, policies, err = f(id, table.POLICY_DIRECTION_EXPORT)
		if err != nil {
			return nil, err
		}
		c.Config.ExportPolicyList = policies
		c.Config.DefaultExportPolicy = rt
		return c, nil
	}

	return s.mgmtOperation(func() error {
		ap := make(map[string]config.ApplyPolicy, len(s.neighborMap)+1)
		a, err := getConfig(table.GLOBAL_RIB_NAME)
		if err != nil {
			return err
		}
		ap[table.GLOBAL_RIB_NAME] = *a
		for _, peer := range s.neighborMap {
			peer.fsm.lock.RLock()
			s.logger.Info("call set policy",
				log.Fields{
					"Topic": "Peer",
					"Key":   peer.fsm.pConf.State.NeighborAddress})
			peer.fsm.lock.RUnlock()
			a, err := getConfig(peer.ID())
			if err != nil {
				return err
			}
			ap[peer.ID()] = *a
		}
		return s.policy.Reset(rp, ap)
	}, false)
}

// EVPN MAC MOBILITY HANDLING
//
// We don't have multihoming function now, so ignore
// ESI comparison.
//
// RFC7432 15. MAC Mobility
//
// A PE detecting a locally attached MAC address for which it had
// previously received a MAC/IP Advertisement route with the same zero
// Ethernet segment identifier (single-homed scenarios) advertises it
// with a MAC Mobility extended community attribute with the sequence
// number set properly.  In the case of single-homed scenarios, there
// is no need for ESI comparison.

func getMacMobilityExtendedCommunity(etag uint32, mac net.HardwareAddr, evpnPaths []*table.Path) *bgp.MacMobilityExtended {
	seqs := make([]struct {
		seq     int
		isLocal bool
	}, 0)

	for _, path := range evpnPaths {
		nlri := path.GetNlri().(*bgp.EVPNNLRI)
		target, ok := nlri.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
		if !ok {
			continue
		}
		if target.ETag == etag && bytes.Equal(target.MacAddress, mac) {
			found := false
			for _, ec := range path.GetExtCommunities() {
				if t, st := ec.GetTypes(); t == bgp.EC_TYPE_EVPN && st == bgp.EC_SUBTYPE_MAC_MOBILITY {
					seqs = append(seqs, struct {
						seq     int
						isLocal bool
					}{int(ec.(*bgp.MacMobilityExtended).Sequence), path.IsLocal()})
					found = true
					break
				}
			}

			if !found {
				seqs = append(seqs, struct {
					seq     int
					isLocal bool
				}{-1, path.IsLocal()})
			}
		}
	}

	if len(seqs) > 0 {
		newSeq := -2
		var isLocal bool
		for _, seq := range seqs {
			if seq.seq > newSeq {
				newSeq = seq.seq
				isLocal = seq.isLocal
			}
		}

		if !isLocal {
			newSeq += 1
		}

		if newSeq != -1 {
			return &bgp.MacMobilityExtended{
				Sequence: uint32(newSeq),
			}
		}
	}
	return nil
}

func (s *BgpServer) fixupApiPath(vrfId string, pathList []*table.Path) error {
	for _, path := range pathList {
		if !path.IsWithdraw {
			if _, err := path.GetOrigin(); err != nil {
				return err
			}
		}

		if vrfId != "" {
			vrf := s.globalRib.Vrfs[vrfId]
			if vrf == nil {
				return fmt.Errorf("vrf %s not found", vrfId)
			}
			if err := vrf.ToGlobalPath(path); err != nil {
				return err
			}
		}

		// Address Family specific Handling
		switch nlri := path.GetNlri().(type) {
		case *bgp.EVPNNLRI:
			switch r := nlri.RouteTypeData.(type) {
			case *bgp.EVPNMacIPAdvertisementRoute:
				// MAC Mobility Extended Community
				paths := s.globalRib.GetBestPathList(table.GLOBAL_RIB_NAME, 0, []bgp.RouteFamily{bgp.RF_EVPN})
				if m := getMacMobilityExtendedCommunity(r.ETag, r.MacAddress, paths); m != nil {
					pm := getMacMobilityExtendedCommunity(r.ETag, r.MacAddress, []*table.Path{path})
					if pm == nil {
						path.SetExtCommunities([]bgp.ExtendedCommunityInterface{m}, false)
					} else if pm != nil && pm.Sequence < m.Sequence {
						return fmt.Errorf("invalid MAC mobility sequence number")
					}
				}
			case *bgp.EVPNEthernetSegmentRoute:
				// RFC7432: BGP MPLS-Based Ethernet VPN
				// 7.6. ES-Import Route Target
				// The value is derived automatically for the ESI Types 1, 2,
				// and 3, by encoding the high-order 6-octet portion of the 9-octet ESI
				// Value, which corresponds to a MAC address, in the ES-Import Route
				// Target.
				// Note: If the given path already has the ES-Import Route Target,
				// skips deriving a new one.
				found := false
				for _, extComm := range path.GetExtCommunities() {
					if _, found = extComm.(*bgp.ESImportRouteTarget); found {
						break
					}
				}
				if !found {
					switch r.ESI.Type {
					case bgp.ESI_LACP, bgp.ESI_MSTP, bgp.ESI_MAC:
						mac := net.HardwareAddr(r.ESI.Value[0:6])
						rt := &bgp.ESImportRouteTarget{ESImport: mac}
						path.SetExtCommunities([]bgp.ExtendedCommunityInterface{rt}, false)
					}
				}
			}
		}
	}
	return nil
}

func pathTokey(path *table.Path) string {
	return fmt.Sprintf("%d:%s", path.GetNlri().PathIdentifier(), path.GetNlri().String())
}

func (s *BgpServer) addPathList(vrfId string, pathList []*table.Path) error {
	err := s.fixupApiPath(vrfId, pathList)
	if err == nil {
		s.propagateUpdate(nil, pathList)
	}
	return err
}

func (s *BgpServer) addPathStream(vrfId string, pathList []*table.Path) error {
	err := s.mgmtOperation(func() error {
		return s.addPathList(vrfId, pathList)
	}, true)
	return err
}

func (s *BgpServer) AddPath(ctx context.Context, r *api.AddPathRequest) (*api.AddPathResponse, error) {
	if r == nil || r.Path == nil {
		return nil, fmt.Errorf("nil request")
	}
	var uuidBytes []byte
	err := s.mgmtOperation(func() error {
		path, err := api2Path(r.TableType, r.Path, false)
		if err != nil {
			return err
		}
		err = s.addPathList(r.VrfId, []*table.Path{path})
		if err != nil {
			return err
		}
		if id, err := uuid.NewRandom(); err == nil {
			s.uuidMap[pathTokey(path)] = id
			uuidBytes, _ = id.MarshalBinary()
		}
		return nil
	}, true)
	return &api.AddPathResponse{Uuid: uuidBytes}, err
}

func (s *BgpServer) DeletePath(ctx context.Context, r *api.DeletePathRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		deletePathList := make([]*table.Path, 0)

		pathList, err := func() ([]*table.Path, error) {
			if r.Path != nil {
				path, err := api2Path(r.TableType, r.Path, true)
				return []*table.Path{path}, err
			}
			return []*table.Path{}, nil
		}()
		if err != nil {
			return err
		}

		if len(r.Uuid) > 0 {
			// Delete locally generated path which has the given UUID
			path := func() *table.Path {
				id, _ := uuid.FromBytes(r.Uuid)
				for k, v := range s.uuidMap {
					if v == id {
						for _, path := range s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, s.globalRib.GetRFlist()) {
							if path.IsLocal() && k == pathTokey(path) {
								delete(s.uuidMap, k)
								return path
							}
						}
					}
				}
				return nil
			}()
			if path == nil {
				return fmt.Errorf("can't find a specified path")
			}
			deletePathList = append(deletePathList, path.Clone(true))
		} else if len(pathList) == 0 {
			// Delete all locally generated paths
			families := s.globalRib.GetRFlist()
			if r.Family != nil {
				families = []bgp.RouteFamily{bgp.AfiSafiToRouteFamily(uint16(r.Family.Afi), uint8(r.Family.Safi))}

			}
			for _, path := range s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, families) {
				if path.IsLocal() {
					deletePathList = append(deletePathList, path.Clone(true))
				}
			}
			s.uuidMap = make(map[string]uuid.UUID)
		} else {
			if err := s.fixupApiPath(r.VrfId, pathList); err != nil {
				return err
			}
			deletePathList = pathList
			for _, p := range deletePathList {
				delete(s.uuidMap, pathTokey(p))
			}
		}
		s.propagateUpdate(nil, deletePathList)
		return nil
	}, true)
}

func (s *BgpServer) updatePath(vrfId string, pathList []*table.Path) error {
	err := s.mgmtOperation(func() error {
		if err := s.fixupApiPath(vrfId, pathList); err != nil {
			return err
		}
		s.propagateUpdate(nil, pathList)
		return nil
	}, true)
	return err
}

func (s *BgpServer) StartBgp(ctx context.Context, r *api.StartBgpRequest) error {
	if r == nil || r.Global == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		g := r.Global
		if net.ParseIP(g.RouterId) == nil {
			return fmt.Errorf("invalid router-id format: %s", g.RouterId)
		}

		c := newGlobalFromAPIStruct(g)
		if err := config.SetDefaultGlobalConfigValues(c); err != nil {
			return err
		}

		if c.Config.Port > 0 {
			acceptCh := make(chan *net.TCPConn, 32)
			for _, addr := range c.Config.LocalAddressList {
				l, err := newTCPListener(s.logger, addr, uint32(c.Config.Port), g.BindToDevice, acceptCh)
				if err != nil {
					return err
				}
				s.listeners = append(s.listeners, l)
			}
			s.acceptCh = acceptCh
		}

		rfs, _ := config.AfiSafis(c.AfiSafis).ToRfList()
		s.globalRib = table.NewTableManager(s.logger, rfs)
		s.rsRib = table.NewTableManager(s.logger, rfs)

		if err := s.policy.Initialize(); err != nil {
			return err
		}
		s.bgpConfig.Global = *c
		// update route selection options
		table.SelectionOptions = c.RouteSelectionOptions.Config
		table.UseMultiplePaths = c.UseMultiplePaths.Config
		return nil
	}, false)
}

// TODO: delete this function
func (s *BgpServer) listVrf() (l []*table.Vrf) {
	s.mgmtOperation(func() error {
		l = make([]*table.Vrf, 0, len(s.globalRib.Vrfs))
		for _, vrf := range s.globalRib.Vrfs {
			l = append(l, vrf.Clone())
		}
		return nil
	}, true)
	return l
}

func (s *BgpServer) ListVrf(ctx context.Context, r *api.ListVrfRequest, fn func(*api.Vrf)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	toApi := func(v *table.Vrf) *api.Vrf {
		d, _ := apiutil.MarshalRD(v.Rd)
		irt, _ := apiutil.MarshalRTs(v.ImportRt)
		ert, _ := apiutil.MarshalRTs(v.ExportRt)
		return &api.Vrf{
			Name:     v.Name,
			Rd:       d,
			Id:       v.Id,
			ImportRt: irt,
			ExportRt: ert,
		}
	}
	var l []*api.Vrf
	s.mgmtOperation(func() error {
		l = make([]*api.Vrf, 0, len(s.globalRib.Vrfs))
		for name, vrf := range s.globalRib.Vrfs {
			if r.Name != "" && r.Name != name {
				continue
			}
			l = append(l, toApi(vrf.Clone()))
		}
		return nil
	}, true)
	for _, v := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(v)
		}
	}
	return nil
}

func (s *BgpServer) AddVrf(ctx context.Context, r *api.AddVrfRequest) error {
	if r == nil || r.Vrf == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		name := r.Vrf.Name
		id := r.Vrf.Id

		rd, err := apiutil.UnmarshalRD(r.Vrf.Rd)
		if err != nil {
			return err
		}
		im, err := apiutil.UnmarshalRTs(r.Vrf.ImportRt)
		if err != nil {
			return err
		}
		ex, err := apiutil.UnmarshalRTs(r.Vrf.ExportRt)
		if err != nil {
			return err
		}

		pi := &table.PeerInfo{
			AS:      s.bgpConfig.Global.Config.As,
			LocalID: net.ParseIP(s.bgpConfig.Global.Config.RouterId).To4(),
		}

		if pathList, err := s.globalRib.AddVrf(name, id, rd, im, ex, pi); err != nil {
			return err
		} else if len(pathList) > 0 {
			s.propagateUpdate(nil, pathList)
		}
		if vrf, ok := s.globalRib.Vrfs[name]; ok {
			if s.zclient != nil && s.zclient.mplsLabel.rangeSize > 0 {
				s.zclient.assignAndSendVrfMplsLabel(vrf)
			}
		}
		return nil
	}, true)
}

func (s *BgpServer) DeleteVrf(ctx context.Context, r *api.DeleteVrfRequest) error {
	if r == nil || r.Name == "" {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		name := r.Name
		for _, n := range s.neighborMap {
			n.fsm.lock.RLock()
			peerVrf := n.fsm.pConf.Config.Vrf
			n.fsm.lock.RUnlock()
			if peerVrf == name {
				return fmt.Errorf("failed to delete VRF %s: neighbor %s is in use", name, n.ID())
			}
		}

		if vrf, ok := s.globalRib.Vrfs[name]; ok {
			if vrf.MplsLabel > 0 {
				s.zclient.releaseMplsLabel(vrf.MplsLabel)
			}
		}
		pathList, err := s.globalRib.DeleteVrf(name)
		if err != nil {
			return err
		}
		if len(pathList) > 0 {
			s.propagateUpdate(nil, pathList)
		}
		return nil
	}, true)
}

func familiesForSoftreset(peer *peer, family bgp.RouteFamily) []bgp.RouteFamily {
	if family == bgp.RouteFamily(0) {
		configured := peer.configuredRFlist()
		families := make([]bgp.RouteFamily, 0, len(configured))
		for _, f := range configured {
			if f != bgp.RF_RTC_UC {
				families = append(families, f)
			}
		}
		return families
	}
	return []bgp.RouteFamily{family}
}

func (s *BgpServer) softResetIn(addr string, family bgp.RouteFamily) error {
	peers, err := s.addrToPeers(addr)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		s.propagateUpdate(peer, peer.adjRibIn.PathList(familiesForSoftreset(peer, family), true))
	}
	return err
}

func (s *BgpServer) softResetOut(addr string, family bgp.RouteFamily, deferral bool) error {
	peers, err := s.addrToPeers(addr)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		peer.fsm.lock.RLock()
		notEstablished := peer.fsm.state != bgp.BGP_FSM_ESTABLISHED
		peer.fsm.lock.RUnlock()
		if notEstablished {
			continue
		}
		families := familiesForSoftreset(peer, family)

		if deferral {
			if family == bgp.RouteFamily(0) {
				families = peer.configuredRFlist()
			}
			peer.fsm.lock.RLock()
			_, y := peer.fsm.rfMap[bgp.RF_RTC_UC]
			c := peer.fsm.pConf.GetAfiSafi(bgp.RF_RTC_UC)
			restarting := peer.fsm.pConf.GracefulRestart.State.LocalRestarting
			peer.fsm.lock.RUnlock()
			if restarting {
				peer.fsm.lock.Lock()
				peer.fsm.pConf.GracefulRestart.State.LocalRestarting = false
				peer.fsm.lock.Unlock()
				s.logger.Debug("deferral timer expired",
					log.Fields{
						"Topic":    "Peer",
						"Key":      peer.ID(),
						"Families": families})
			} else if y && !c.MpGracefulRestart.State.EndOfRibReceived {
				s.logger.Debug("route-target deferral timer expired",
					log.Fields{
						"Topic":    "Peer",
						"Key":      peer.ID(),
						"Families": families})
			} else {
				continue
			}
		}

		pathList, _ := s.getBestFromLocal(peer, families)
		if len(pathList) > 0 {
			if deferral {
				pathList = func() []*table.Path {
					l := make([]*table.Path, 0, len(pathList))
					for _, p := range pathList {
						if !p.IsWithdraw {
							l = append(l, p)
						}
					}
					return l
				}()
			}
			sendfsmOutgoingMsg(peer, pathList, nil, false)
		}
	}
	return nil
}

func (s *BgpServer) sResetIn(addr string, family bgp.RouteFamily) error {
	s.logger.Info("Neighbor soft reset in",
		log.Fields{
			"Topic": "Operation",
			"Key":   addr})
	return s.softResetIn(addr, family)
}

func (s *BgpServer) sResetOut(addr string, family bgp.RouteFamily) error {
	s.logger.Info("Neighbor soft reset out",
		log.Fields{
			"Topic": "Operation",
			"Key":   addr})
	return s.softResetOut(addr, family, false)
}

func (s *BgpServer) sReset(addr string, family bgp.RouteFamily) error {
	s.logger.Info("Neighbor soft reset",
		log.Fields{
			"Topic": "Operation",
			"Key":   addr})
	err := s.softResetIn(addr, family)
	if err != nil {
		return err
	}
	return s.softResetOut(addr, family, false)
}

func (s *BgpServer) validateTable(r *table.Table) (v map[*table.Path]*table.Validation) {
	if s.roaManager.enabled() {
		v = make(map[*table.Path]*table.Validation, len(r.GetDestinations()))
		for _, d := range r.GetDestinations() {
			for _, p := range d.GetAllKnownPathList() {
				v[p] = s.roaTable.Validate(p)
			}
		}
	}
	return
}

func (s *BgpServer) getRib(addr string, family bgp.RouteFamily, prefixes []*table.LookupPrefix) (rib *table.Table, v map[*table.Path]*table.Validation, err error) {
	err = s.mgmtOperation(func() error {
		m := s.globalRib
		id := table.GLOBAL_RIB_NAME
		as := uint32(0)
		if len(addr) > 0 {
			peer, ok := s.neighborMap[addr]
			if !ok {
				return fmt.Errorf("neighbor that has %v doesn't exist", addr)
			}
			if !peer.isRouteServerClient() {
				return fmt.Errorf("neighbor %v doesn't have local rib", addr)
			}
			id = peer.ID()
			as = peer.AS()
			m = s.rsRib
		}
		af := bgp.RouteFamily(family)
		tbl, ok := m.Tables[af]
		if !ok {
			return fmt.Errorf("address family: %s not supported", af)
		}
		rib, err = tbl.Select(table.TableSelectOption{ID: id, AS: as, LookupPrefixes: prefixes})
		v = s.validateTable(rib)
		return err
	}, true)
	return
}

func (s *BgpServer) getVrfRib(name string, family bgp.RouteFamily, prefixes []*table.LookupPrefix) (rib *table.Table, err error) {
	err = s.mgmtOperation(func() error {
		m := s.globalRib
		vrfs := m.Vrfs
		if _, ok := vrfs[name]; !ok {
			return fmt.Errorf("vrf %s not found", name)
		}
		var af bgp.RouteFamily
		switch family {
		case bgp.RF_IPv4_UC:
			af = bgp.RF_IPv4_VPN
		case bgp.RF_IPv6_UC:
			af = bgp.RF_IPv6_VPN
		case bgp.RF_FS_IPv4_UC:
			af = bgp.RF_FS_IPv4_VPN
		case bgp.RF_FS_IPv6_UC:
			af = bgp.RF_FS_IPv6_VPN
		case bgp.RF_EVPN:
			af = bgp.RF_EVPN
		}
		tbl, ok := m.Tables[af]
		if !ok {
			return fmt.Errorf("address family: %s not supported", af)
		}
		rib, err = tbl.Select(table.TableSelectOption{VRF: vrfs[name], LookupPrefixes: prefixes})
		return err
	}, true)
	return
}

func (s *BgpServer) getAdjRib(addr string, family bgp.RouteFamily, in bool, enableFiltered bool, prefixes []*table.LookupPrefix) (rib *table.Table, filtered map[string]*table.Path, v map[*table.Path]*table.Validation, err error) {
	err = s.mgmtOperation(func() error {
		peer, ok := s.neighborMap[addr]
		if !ok {
			return fmt.Errorf("neighbor that has %v doesn't exist", addr)
		}
		id := peer.ID()
		as := peer.AS()

		var adjRib *table.AdjRib
		filtered = make(map[string]*table.Path)
		if in {
			adjRib = peer.adjRibIn
			if enableFiltered {
				for _, path := range peer.adjRibIn.PathList([]bgp.RouteFamily{family}, true) {
					options := &table.PolicyOptions{
						Validate: s.roaTable.Validate,
					}
					if s.policy.ApplyPolicy(peer.TableID(), table.POLICY_DIRECTION_IMPORT, path, options) == nil {
						filtered[path.GetNlri().String()] = path
					}
				}
			}
		} else {
			adjRib = table.NewAdjRib(s.logger, peer.configuredRFlist())
			if enableFiltered {
				for _, path := range s.getPossibleBest(peer, family) {
					path, options, stop := s.prePolicyFilterpath(peer, path, nil)
					if stop {
						continue
					}
					options.Validate = s.roaTable.Validate
					p := peer.policy.ApplyPolicy(peer.TableID(), table.POLICY_DIRECTION_EXPORT, path, options)
					if p == nil {
						filtered[path.GetNlri().String()] = path
					}
					adjRib.UpdateAdjRibOut([]*table.Path{path})
				}
			} else {
				accepted, _ := s.getBestFromLocal(peer, peer.configuredRFlist())
				adjRib.UpdateAdjRibOut(accepted)
			}
		}
		rib, err = adjRib.Select(family, false, table.TableSelectOption{ID: id, AS: as, LookupPrefixes: prefixes})
		v = s.validateTable(rib)
		return err
	}, true)
	return
}

func (s *BgpServer) ListPath(ctx context.Context, r *api.ListPathRequest, fn func(*api.Destination)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var tbl *table.Table
	var v map[*table.Path]*table.Validation
	var filtered map[string]*table.Path

	f := func() []*table.LookupPrefix {
		l := make([]*table.LookupPrefix, 0, len(r.Prefixes))
		for _, p := range r.Prefixes {
			l = append(l, &table.LookupPrefix{
				Prefix:       p.Prefix,
				LookupOption: table.LookupOption(p.Type),
			})
		}
		return l
	}

	in := false
	family := bgp.RouteFamily(0)
	if r.Family != nil {
		family = bgp.AfiSafiToRouteFamily(uint16(r.Family.Afi), uint8(r.Family.Safi))
	}
	var err error
	switch r.TableType {
	case api.TableType_LOCAL, api.TableType_GLOBAL:
		tbl, v, err = s.getRib(r.Name, family, f())
	case api.TableType_ADJ_IN:
		in = true
		fallthrough
	case api.TableType_ADJ_OUT:
		tbl, filtered, v, err = s.getAdjRib(r.Name, family, in, r.EnableFiltered, f())
	case api.TableType_VRF:
		tbl, err = s.getVrfRib(r.Name, family, []*table.LookupPrefix{})
	default:
		return fmt.Errorf("unsupported resource type: %v", r.TableType)
	}

	if err != nil {
		return err
	}

	err = func() error {
		for _, dst := range tbl.GetDestinations() {
			d := api.Destination{
				Prefix: dst.GetNlri().String(),
				Paths:  make([]*api.Path, 0, len(dst.GetAllKnownPathList())),
			}
			knownPathList := dst.GetAllKnownPathList()
			for i, path := range knownPathList {
				p := toPathApi(path, getValidation(v, path), r.EnableNlriBinary, r.EnableAttributeBinary)
				if !table.SelectionOptions.DisableBestPathSelection {
					if i == 0 {
						switch r.TableType {
						case api.TableType_LOCAL, api.TableType_GLOBAL:
							p.Best = true
						}
					} else if s.bgpConfig.Global.UseMultiplePaths.Config.Enabled && path.Equal(knownPathList[i-1]) {
						p.Best = true
					}
				}
				d.Paths = append(d.Paths, p)
				if r.EnableFiltered {
					if _, ok := filtered[path.GetNlri().String()]; ok {
						p.Filtered = true
					}
				}
			}

			select {
			case <-ctx.Done():
				return nil
			default:
				fn(&d)
			}
		}
		return nil
	}()
	return err
}

func (s *BgpServer) getRibInfo(addr string, family bgp.RouteFamily) (info *table.TableInfo, err error) {
	err = s.mgmtOperation(func() error {
		m := s.globalRib
		id := table.GLOBAL_RIB_NAME
		as := uint32(0)
		if len(addr) > 0 {
			peer, ok := s.neighborMap[addr]
			if !ok {
				return fmt.Errorf("neighbor that has %v doesn't exist", addr)
			}
			if !peer.isRouteServerClient() {
				return fmt.Errorf("neighbor %v doesn't have local rib", addr)
			}
			id = peer.ID()
			as = peer.AS()
			m = s.rsRib
		}

		af := bgp.RouteFamily(family)
		tbl, ok := m.Tables[af]
		if !ok {
			return fmt.Errorf("address family: %s not supported", af)
		}

		info = tbl.Info(table.TableInfoOptions{ID: id, AS: as})

		return err
	}, true)
	return
}

func (s *BgpServer) getAdjRibInfo(addr string, family bgp.RouteFamily, in bool) (info *table.TableInfo, err error) {
	err = s.mgmtOperation(func() error {
		peer, ok := s.neighborMap[addr]
		if !ok {
			return fmt.Errorf("neighbor that has %v doesn't exist", addr)
		}

		var adjRib *table.AdjRib
		if in {
			adjRib = peer.adjRibIn
		} else {
			adjRib = table.NewAdjRib(s.logger, peer.configuredRFlist())
			accepted, _ := s.getBestFromLocal(peer, peer.configuredRFlist())
			adjRib.UpdateAdjRibOut(accepted)
		}
		info, err = adjRib.TableInfo(family)
		return err
	}, true)
	return
}

func (s *BgpServer) getVrfRibInfo(name string, family bgp.RouteFamily) (info *table.TableInfo, err error) {
	err = s.mgmtOperation(func() error {
		m := s.globalRib
		vrfs := m.Vrfs
		if _, ok := vrfs[name]; !ok {
			return fmt.Errorf("vrf %s not found", name)
		}

		var af bgp.RouteFamily
		switch family {
		case bgp.RF_IPv4_UC:
			af = bgp.RF_IPv4_VPN
		case bgp.RF_IPv6_UC:
			af = bgp.RF_IPv6_VPN
		case bgp.RF_FS_IPv4_UC:
			af = bgp.RF_FS_IPv4_VPN
		case bgp.RF_FS_IPv6_UC:
			af = bgp.RF_FS_IPv6_VPN
		case bgp.RF_EVPN:
			af = bgp.RF_EVPN
		}

		tbl, ok := m.Tables[af]
		if !ok {
			return fmt.Errorf("address family: %s not supported", af)
		}

		info = tbl.Info(table.TableInfoOptions{VRF: vrfs[name]})

		return err
	}, true)
	return
}

func (s *BgpServer) GetTable(ctx context.Context, r *api.GetTableRequest) (*api.GetTableResponse, error) {
	if r == nil || r.Family == nil {
		return nil, fmt.Errorf("nil request")
	}
	family := bgp.RouteFamily(0)
	if r.Family != nil {
		family = bgp.AfiSafiToRouteFamily(uint16(r.Family.Afi), uint8(r.Family.Safi))
	}
	var in bool
	var err error
	var info *table.TableInfo
	switch r.TableType {
	case api.TableType_GLOBAL, api.TableType_LOCAL:
		info, err = s.getRibInfo(r.Name, family)
	case api.TableType_ADJ_IN:
		in = true
		fallthrough
	case api.TableType_ADJ_OUT:
		info, err = s.getAdjRibInfo(r.Name, family, in)
	case api.TableType_VRF:
		info, err = s.getVrfRibInfo(r.Name, family)
	default:
		return nil, fmt.Errorf("unsupported resource type: %s", r.TableType)
	}

	if err != nil {
		return nil, err
	}

	return &api.GetTableResponse{
		NumDestination: uint64(info.NumDestination),
		NumPath:        uint64(info.NumPath),
		NumAccepted:    uint64(info.NumAccepted),
	}, nil
}

func (s *BgpServer) GetBgp(ctx context.Context, r *api.GetBgpRequest) (*api.GetBgpResponse, error) {
	if r == nil {
		return nil, fmt.Errorf("nil request")
	}
	var rsp *api.GetBgpResponse
	s.mgmtOperation(func() error {
		g := s.bgpConfig.Global
		rsp = &api.GetBgpResponse{
			Global: &api.Global{
				Asn:              g.Config.As,
				RouterId:         g.Config.RouterId,
				ListenPort:       g.Config.Port,
				ListenAddresses:  g.Config.LocalAddressList,
				UseMultiplePaths: g.UseMultiplePaths.Config.Enabled,
			},
		}
		return nil
	}, false)
	return rsp, nil
}

func (s *BgpServer) ListDynamicNeighbor(ctx context.Context, r *api.ListDynamicNeighborRequest, fn func(neighbor *api.DynamicNeighbor)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	toApi := func(dn *config.DynamicNeighbor) *api.DynamicNeighbor {
		return &api.DynamicNeighbor{
			Prefix:    dn.Config.Prefix,
			PeerGroup: dn.Config.PeerGroup,
		}
	}
	var l []*api.DynamicNeighbor
	s.mgmtOperation(func() error {
		peerGroupName := r.PeerGroup
		for k, group := range s.peerGroupMap {
			if peerGroupName != "" && peerGroupName != k {
				continue
			}
			for _, dn := range group.dynamicNeighbors {
				l = append(l, toApi(dn))
			}
		}
		return nil
	}, false)
	for _, dn := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(dn)
		}
	}
	return nil
}

func (s *BgpServer) ListPeerGroup(ctx context.Context, r *api.ListPeerGroupRequest, fn func(*api.PeerGroup)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var l []*api.PeerGroup
	s.mgmtOperation(func() error {
		peerGroupName := r.PeerGroupName
		l = make([]*api.PeerGroup, 0, len(s.peerGroupMap))
		for k, group := range s.peerGroupMap {
			if peerGroupName != "" && peerGroupName != k {
				continue
			}
			pg := config.NewPeerGroupFromConfigStruct(group.Conf)
			l = append(l, pg)
		}
		return nil
	}, false)
	for _, pg := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(pg)
		}
	}
	return nil
}

func (s *BgpServer) ListPeer(ctx context.Context, r *api.ListPeerRequest, fn func(*api.Peer)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var l []*api.Peer
	s.mgmtOperation(func() error {
		address := r.Address
		getAdvertised := r.EnableAdvertised
		l = make([]*api.Peer, 0, len(s.neighborMap))
		for k, peer := range s.neighborMap {
			peer.fsm.lock.RLock()
			neighborIface := peer.fsm.pConf.Config.NeighborInterface
			peer.fsm.lock.RUnlock()
			if address != "" && address != k && address != neighborIface {
				continue
			}
			// FIXME: should remove toConfig() conversion
			p := config.NewPeerFromConfigStruct(s.toConfig(peer, getAdvertised))
			for _, family := range peer.configuredRFlist() {
				for i, afisafi := range p.AfiSafis {
					if !afisafi.Config.Enabled {
						continue
					}
					afi, safi := bgp.RouteFamilyToAfiSafi(family)
					c := afisafi.Config
					if c.Family != nil && c.Family.Afi == api.Family_Afi(afi) && c.Family.Safi == api.Family_Safi(safi) {
						flist := []bgp.RouteFamily{family}
						received := uint64(peer.adjRibIn.Count(flist))
						accepted := uint64(peer.adjRibIn.Accepted(flist))
						advertised := uint64(0)
						if getAdvertised {
							pathList, _ := s.getBestFromLocal(peer, flist)
							advertised = uint64(len(pathList))
						}
						p.AfiSafis[i].State = &api.AfiSafiState{
							Family:     c.Family,
							Enabled:    true,
							Received:   received,
							Accepted:   accepted,
							Advertised: advertised,
						}
					}
				}
			}
			l = append(l, p)
		}
		return nil
	}, false)
	for _, p := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(p)
		}
	}
	return nil
}

func (s *BgpServer) addPeerGroup(c *config.PeerGroup) error {
	name := c.Config.PeerGroupName
	if _, y := s.peerGroupMap[name]; y {
		return fmt.Errorf("can't overwrite the existing peer-group: %s", name)
	}

	s.logger.Info("Add a peer group configuration",
		log.Fields{
			"Topic": "Peer",
			"Name":  name})

	s.peerGroupMap[c.Config.PeerGroupName] = newPeerGroup(c)

	return nil
}

func (s *BgpServer) addNeighbor(c *config.Neighbor) error {
	addr, err := c.ExtractNeighborAddress()
	if err != nil {
		return err
	}

	if _, y := s.neighborMap[addr]; y {
		return fmt.Errorf("can't overwrite the existing peer: %s", addr)
	}

	var pgConf *config.PeerGroup
	if c.Config.PeerGroup != "" {
		pg, ok := s.peerGroupMap[c.Config.PeerGroup]
		if !ok {
			return fmt.Errorf("no such peer-group: %s", c.Config.PeerGroup)
		}
		pgConf = pg.Conf
	}

	if err := config.SetDefaultNeighborConfigValues(c, pgConf, &s.bgpConfig.Global); err != nil {
		return err
	}

	if vrf := c.Config.Vrf; vrf != "" {
		if c.RouteServer.Config.RouteServerClient {
			return fmt.Errorf("route server client can't be enslaved to VRF")
		}
		families, _ := config.AfiSafis(c.AfiSafis).ToRfList()
		for _, f := range families {
			if f != bgp.RF_IPv4_UC && f != bgp.RF_IPv6_UC && f != bgp.RF_FS_IPv4_UC && f != bgp.RF_FS_IPv6_UC {
				return fmt.Errorf("%s is not supported for VRF enslaved neighbor", f)
			}
		}
		_, y := s.globalRib.Vrfs[vrf]
		if !y {
			return fmt.Errorf("VRF not found: %s", vrf)
		}
	}

	if c.RouteServer.Config.RouteServerClient && c.RouteReflector.Config.RouteReflectorClient {
		return fmt.Errorf("can't be both route-server-client and route-reflector-client")
	}

	if s.bgpConfig.Global.Config.Port > 0 {
		for _, l := range s.listListeners(addr) {
			if c.Config.AuthPassword != "" {
				if err := setTCPMD5SigSockopt(l, addr, c.Config.AuthPassword); err != nil {
					s.logger.Warn("failed to set md5",
						log.Fields{
							"Topic": "Peer",
							"Key":   addr,
							"Err":   err})
				}
			}
		}
	}
	s.logger.Info("Add a peer configuration",
		log.Fields{
			"Topic": "Peer",
			"Key":   addr})

	rib := s.globalRib
	if c.RouteServer.Config.RouteServerClient {
		rib = s.rsRib
	}
	peer := newPeer(&s.bgpConfig.Global, c, rib, s.policy, s.logger)
	s.addIncoming(peer.fsm.incomingCh)
	s.policy.SetPeerPolicy(peer.ID(), c.ApplyPolicy)
	s.neighborMap[addr] = peer
	if name := c.Config.PeerGroup; name != "" {
		s.peerGroupMap[name].AddMember(*c)
	}
	peer.startFSMHandler()
	s.broadcastPeerState(peer, bgp.BGP_FSM_IDLE, nil)
	return nil
}

func (s *BgpServer) AddPeerGroup(ctx context.Context, r *api.AddPeerGroupRequest) error {
	if r == nil || r.PeerGroup == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		c, err := newPeerGroupFromAPIStruct(r.PeerGroup)
		if err != nil {
			return err
		}
		return s.addPeerGroup(c)
	}, true)
}

func (s *BgpServer) AddPeer(ctx context.Context, r *api.AddPeerRequest) error {
	if r == nil || r.Peer == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		c, err := newNeighborFromAPIStruct(r.Peer)
		if err != nil {
			return err
		}
		return s.addNeighbor(c)
	}, true)
}

func (s *BgpServer) AddDynamicNeighbor(ctx context.Context, r *api.AddDynamicNeighborRequest) error {
	if r == nil || r.DynamicNeighbor == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		c := &config.DynamicNeighbor{Config: config.DynamicNeighborConfig{
			Prefix:    r.DynamicNeighbor.Prefix,
			PeerGroup: r.DynamicNeighbor.PeerGroup},
		}
		s.peerGroupMap[c.Config.PeerGroup].AddDynamicNeighbor(c)
		return nil
	}, true)
}

func (s *BgpServer) deletePeerGroup(name string) error {
	if _, y := s.peerGroupMap[name]; !y {
		return fmt.Errorf("can't delete a peer-group %s which does not exist", name)
	}

	s.logger.Info("Delete a peer group configuration",
		log.Fields{
			"Topic": "Peer",
			"Name":  name})

	delete(s.peerGroupMap, name)
	return nil
}

func (s *BgpServer) deleteNeighbor(c *config.Neighbor, code, subcode uint8) error {
	if c.Config.PeerGroup != "" {
		_, y := s.peerGroupMap[c.Config.PeerGroup]
		if y {
			s.peerGroupMap[c.Config.PeerGroup].DeleteMember(*c)
		}
	}

	addr, err := c.ExtractNeighborAddress()
	if err != nil {
		return err
	}

	if intf := c.Config.NeighborInterface; intf != "" {
		var err error
		addr, err = config.GetIPv6LinkLocalNeighborAddress(intf)
		if err != nil {
			return err
		}
	}
	n, y := s.neighborMap[addr]
	if !y {
		return fmt.Errorf("can't delete a peer configuration for %s", addr)
	}
	for _, l := range s.listListeners(addr) {
		if c.Config.AuthPassword != "" {
			if err := setTCPMD5SigSockopt(l, addr, ""); err != nil {
				s.logger.Warn("failed to unset md5",
					log.Fields{
						"Topic": "Peer",
						"Key":   addr,
						"Err":   err})
			}
		}
	}
	s.logger.Info("Delete a peer configuration",
		log.Fields{
			"Topic": "Peer",
			"Key":   addr})

	n.stopPeerRestarting()
	n.fsm.notification <- bgp.NewBGPNotificationMessage(code, subcode, nil)
	n.fsm.h.ctxCancel()

	delete(s.neighborMap, addr)
	s.propagateUpdate(n, n.DropAll(n.configuredRFlist()))
	return nil
}

func (s *BgpServer) DeletePeerGroup(ctx context.Context, r *api.DeletePeerGroupRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		name := r.Name
		for _, n := range s.neighborMap {
			n.fsm.lock.RLock()
			peerGroup := n.fsm.pConf.Config.PeerGroup
			n.fsm.lock.RUnlock()
			if peerGroup == name {
				return fmt.Errorf("failed to delete peer-group %s: neighbor %s is in use", name, n.ID())
			}
		}
		return s.deletePeerGroup(name)
	}, true)
}

func (s *BgpServer) DeletePeer(ctx context.Context, r *api.DeletePeerRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		c := &config.Neighbor{Config: config.NeighborConfig{
			NeighborAddress:   r.Address,
			NeighborInterface: r.Interface,
		}}
		return s.deleteNeighbor(c, bgp.BGP_ERROR_CEASE, bgp.BGP_ERROR_SUB_PEER_DECONFIGURED)
	}, true)
}

func (s *BgpServer) DeleteDynamicNeighbor(ctx context.Context, r *api.DeleteDynamicNeighborRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		s.peerGroupMap[r.PeerGroup].DeleteDynamicNeighbor(r.Prefix)
		return nil
	}, true)
}

func (s *BgpServer) updatePeerGroup(pg *config.PeerGroup) (needsSoftResetIn bool, err error) {
	name := pg.Config.PeerGroupName

	_, ok := s.peerGroupMap[name]
	if !ok {
		return false, fmt.Errorf("peer-group %s doesn't exist", name)
	}
	s.peerGroupMap[name].Conf = pg

	for _, n := range s.peerGroupMap[name].members {
		c := n
		u, err := s.updateNeighbor(&c)
		if err != nil {
			return needsSoftResetIn, err
		}
		needsSoftResetIn = needsSoftResetIn || u
	}
	return needsSoftResetIn, nil
}

func (s *BgpServer) UpdatePeerGroup(ctx context.Context, r *api.UpdatePeerGroupRequest) (rsp *api.UpdatePeerGroupResponse, err error) {
	if r == nil || r.PeerGroup == nil {
		return nil, fmt.Errorf("nil request")
	}
	doSoftreset := false
	err = s.mgmtOperation(func() error {
		pg, err := newPeerGroupFromAPIStruct(r.PeerGroup)
		if err != nil {
			return err
		}
		doSoftreset, err = s.updatePeerGroup(pg)
		return err
	}, true)
	return &api.UpdatePeerGroupResponse{NeedsSoftResetIn: doSoftreset}, err
}

func (s *BgpServer) updateNeighbor(c *config.Neighbor) (needsSoftResetIn bool, err error) {
	if c.Config.PeerGroup != "" {
		if pg, ok := s.peerGroupMap[c.Config.PeerGroup]; ok {
			if err := config.SetDefaultNeighborConfigValues(c, pg.Conf, &s.bgpConfig.Global); err != nil {
				return needsSoftResetIn, err
			}
		} else {
			return needsSoftResetIn, fmt.Errorf("no such peer-group: %s", c.Config.PeerGroup)
		}
	}

	addr, err := c.ExtractNeighborAddress()
	if err != nil {
		return needsSoftResetIn, err
	}

	peer, ok := s.neighborMap[addr]
	if !ok {
		return needsSoftResetIn, fmt.Errorf("neighbor that has %v doesn't exist", addr)
	}

	if !peer.fsm.pConf.ApplyPolicy.Equal(&c.ApplyPolicy) {
		s.logger.Info("Update ApplyPolicy",
			log.Fields{
				"Topic": "Peer",
				"Key":   addr})

		s.policy.SetPeerPolicy(peer.ID(), c.ApplyPolicy)
		peer.fsm.pConf.ApplyPolicy = c.ApplyPolicy
		needsSoftResetIn = true
	}
	original := peer.fsm.pConf

	if !original.AsPathOptions.Config.Equal(&c.AsPathOptions.Config) {
		s.logger.Info("Update aspath options",
			log.Fields{
				"Topic": "Peer",
				"Key":   peer.ID()})
		needsSoftResetIn = true
	}

	if original.NeedsResendOpenMessage(c) {
		sub := uint8(bgp.BGP_ERROR_SUB_OTHER_CONFIGURATION_CHANGE)
		if original.Config.AdminDown != c.Config.AdminDown {
			sub = bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN
			state := "Admin Down"

			if !c.Config.AdminDown {
				state = "Admin Up"
			}
			s.logger.Info("Update admin-state configuration",
				log.Fields{
					"Topic": "Peer",
					"Key":   peer.ID(),
					"State": state})
		} else if original.Config.PeerAs != c.Config.PeerAs {
			sub = bgp.BGP_ERROR_SUB_PEER_DECONFIGURED
		}
		if err = s.deleteNeighbor(peer.fsm.pConf, bgp.BGP_ERROR_CEASE, sub); err != nil {
			s.logger.Error("failed to delete neighbor",
				log.Fields{
					"Topic": "Peer",
					"Key":   addr,
					"Err":   err})
			return needsSoftResetIn, err
		}
		err = s.addNeighbor(c)
		if err != nil {
			s.logger.Error("failed to add neighbor",
				log.Fields{
					"Topic": "Peer",
					"Key":   addr,
					"Err":   err})
		}
		return needsSoftResetIn, err
	}

	if !original.Timers.Config.Equal(&c.Timers.Config) {
		s.logger.Info("Update timer configuration",
			log.Fields{
				"Topic": "Peer",
				"Key":   peer.ID(),
				"Err":   err})
		peer.fsm.pConf.Timers.Config = c.Timers.Config
	}

	err = peer.updatePrefixLimitConfig(c.AfiSafis)
	if err != nil {
		s.logger.Error("failed to update prefixLimit",
			log.Fields{
				"Topic": "Peer",
				"Key":   addr,
				"Err":   err})
		// rollback to original state
		peer.fsm.pConf = original
	}
	return needsSoftResetIn, err
}

func (s *BgpServer) UpdatePeer(ctx context.Context, r *api.UpdatePeerRequest) (rsp *api.UpdatePeerResponse, err error) {
	if r == nil || r.Peer == nil {
		return nil, fmt.Errorf("nil request")
	}
	doSoftReset := false
	err = s.mgmtOperation(func() error {
		c, err := newNeighborFromAPIStruct(r.Peer)
		if err != nil {
			return err
		}
		doSoftReset, err = s.updateNeighbor(c)
		return err
	}, true)
	return &api.UpdatePeerResponse{NeedsSoftResetIn: doSoftReset}, err
}

func (s *BgpServer) addrToPeers(addr string) (l []*peer, err error) {
	if len(addr) == 0 {
		for _, p := range s.neighborMap {
			l = append(l, p)
		}
		return l, nil
	}
	p, found := s.neighborMap[addr]
	if !found {
		return l, fmt.Errorf("neighbor that has %v doesn't exist", addr)
	}
	return []*peer{p}, nil
}

func (s *BgpServer) sendNotification(op, addr string, subcode uint8, data []byte) error {
	s.logger.Info("Send operation notification",
		log.Fields{
			"Topic": "Operation",
			"Key":   addr,
			"Op":    op})

	peers, err := s.addrToPeers(addr)
	if err == nil {
		m := bgp.NewBGPNotificationMessage(bgp.BGP_ERROR_CEASE, subcode, data)
		for _, peer := range peers {
			sendfsmOutgoingMsg(peer, nil, m, false)
		}
	}
	return err
}

func (s *BgpServer) ShutdownPeer(ctx context.Context, r *api.ShutdownPeerRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.sendNotification("Neighbor shutdown", r.Address, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN, newAdministrativeCommunication(r.Communication))
	}, true)
}

func (s *BgpServer) ResetPeer(ctx context.Context, r *api.ResetPeerRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		addr := r.Address
		comm := r.Communication
		if r.Soft {
			var err error
			if addr == "all" {
				addr = ""
			}
			family := bgp.RouteFamily(0)
			switch r.Direction {
			case api.ResetPeerRequest_IN:
				err = s.sResetIn(addr, family)
			case api.ResetPeerRequest_OUT:
				err = s.sResetOut(addr, family)
			case api.ResetPeerRequest_BOTH:
				err = s.sReset(addr, family)
			default:
				err = fmt.Errorf("unknown direction")
			}
			return err
		}

		err := s.sendNotification("Neighbor reset", addr, bgp.BGP_ERROR_SUB_ADMINISTRATIVE_RESET, newAdministrativeCommunication(comm))
		if err != nil {
			return err
		}
		peers, _ := s.addrToPeers(addr)
		for _, peer := range peers {
			peer.fsm.lock.Lock()
			peer.fsm.idleHoldTime = peer.fsm.pConf.Timers.Config.IdleHoldTimeAfterReset
			peer.fsm.lock.Unlock()
		}
		return nil
	}, true)
}

func (s *BgpServer) setAdminState(addr, communication string, enable bool) error {
	peers, err := s.addrToPeers(addr)
	if err != nil {
		return err
	}
	for _, peer := range peers {
		f := func(stateOp *adminStateOperation, message string) {
			select {
			case peer.fsm.adminStateCh <- *stateOp:
				peer.fsm.lock.RLock()
				s.logger.Debug("set admin state",
					log.Fields{
						"Topic":   "Peer",
						"Key":     peer.fsm.pConf.State.NeighborAddress,
						"Message": message})
				peer.fsm.lock.RUnlock()
			default:
				peer.fsm.lock.RLock()
				s.logger.Warn("previous setting admin state request is still remaining",
					log.Fields{
						"Topic": "Peer",
						"Key":   peer.fsm.pConf.State.NeighborAddress})
				peer.fsm.lock.RUnlock()
			}
		}
		if enable {
			f(&adminStateOperation{adminStateUp, nil}, "adminStateUp requested")
		} else {
			f(&adminStateOperation{adminStateDown, newAdministrativeCommunication(communication)}, "adminStateDown requested")
		}
	}
	return nil
}

func (s *BgpServer) EnablePeer(ctx context.Context, r *api.EnablePeerRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.setAdminState(r.Address, "", true)
	}, true)
}

func (s *BgpServer) DisablePeer(ctx context.Context, r *api.DisablePeerRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.setAdminState(r.Address, r.Communication, false)
	}, true)
}

func (s *BgpServer) ListDefinedSet(ctx context.Context, r *api.ListDefinedSetRequest, fn func(*api.DefinedSet)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var cd *config.DefinedSets
	var err error
	err = s.mgmtOperation(func() error {
		cd, err = s.policy.GetDefinedSet(table.DefinedType(r.DefinedType), r.Name)
		return err
	}, false)

	if err != nil {
		return err
	}
	exec := func(d *api.DefinedSet) bool {
		select {
		case <-ctx.Done():
			return true
		default:
			fn(d)
		}
		return false
	}

	for _, cs := range cd.PrefixSets {
		ad := &api.DefinedSet{
			DefinedType: api.DefinedType_PREFIX,
			Name:        cs.PrefixSetName,
			Prefixes: func() []*api.Prefix {
				l := make([]*api.Prefix, 0, len(cs.PrefixList))
				for _, p := range cs.PrefixList {
					elems := _regexpPrefixMaskLengthRange.FindStringSubmatch(p.MasklengthRange)
					min, _ := strconv.ParseUint(elems[1], 10, 32)
					max, _ := strconv.ParseUint(elems[2], 10, 32)

					l = append(l, &api.Prefix{IpPrefix: p.IpPrefix, MaskLengthMin: uint32(min), MaskLengthMax: uint32(max)})
				}
				return l
			}(),
		}
		if exec(ad) {
			return nil
		}
	}
	for _, cs := range cd.NeighborSets {
		ad := &api.DefinedSet{
			DefinedType: api.DefinedType_NEIGHBOR,
			Name:        cs.NeighborSetName,
			List:        cs.NeighborInfoList,
		}
		if exec(ad) {
			return nil
		}
	}
	for _, cs := range cd.BgpDefinedSets.CommunitySets {
		ad := &api.DefinedSet{
			DefinedType: api.DefinedType_COMMUNITY,
			Name:        cs.CommunitySetName,
			List:        cs.CommunityList,
		}
		if exec(ad) {
			return nil
		}
	}
	for _, cs := range cd.BgpDefinedSets.ExtCommunitySets {
		ad := &api.DefinedSet{
			DefinedType: api.DefinedType_EXT_COMMUNITY,
			Name:        cs.ExtCommunitySetName,
			List:        cs.ExtCommunityList,
		}
		if exec(ad) {
			return nil
		}
	}
	for _, cs := range cd.BgpDefinedSets.LargeCommunitySets {
		ad := &api.DefinedSet{
			DefinedType: api.DefinedType_LARGE_COMMUNITY,
			Name:        cs.LargeCommunitySetName,
			List:        cs.LargeCommunityList,
		}
		if exec(ad) {
			return nil
		}
	}
	for _, cs := range cd.BgpDefinedSets.AsPathSets {
		ad := &api.DefinedSet{
			DefinedType: api.DefinedType_AS_PATH,
			Name:        cs.AsPathSetName,
			List:        cs.AsPathList,
		}
		if exec(ad) {
			return nil
		}
	}
	return nil
}

func (s *BgpServer) AddDefinedSet(ctx context.Context, r *api.AddDefinedSetRequest) error {
	if r == nil || r.DefinedSet == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		set, err := newDefinedSetFromApiStruct(r.DefinedSet)
		if err != nil {
			return err
		}
		return s.policy.AddDefinedSet(set)
	}, false)
}

func (s *BgpServer) DeleteDefinedSet(ctx context.Context, r *api.DeleteDefinedSetRequest) error {
	if r == nil || r.DefinedSet == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		set, err := newDefinedSetFromApiStruct(r.DefinedSet)
		if err != nil {
			return err
		}
		return s.policy.DeleteDefinedSet(set, r.All)
	}, false)
}

func (s *BgpServer) ListStatement(ctx context.Context, r *api.ListStatementRequest, fn func(*api.Statement)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var l []*api.Statement
	s.mgmtOperation(func() error {
		s := s.policy.GetStatement(r.Name)
		l = make([]*api.Statement, 0, len(s))
		for _, st := range s {
			l = append(l, toStatementApi(st))
		}
		return nil
	}, false)
	for _, s := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(s)
		}
	}
	return nil
}

func (s *BgpServer) AddStatement(ctx context.Context, r *api.AddStatementRequest) error {
	if r == nil || r.Statement == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		st, err := newStatementFromApiStruct(r.Statement)
		if err != nil {
			return err
		}
		return s.policy.AddStatement(st)
	}, false)
}

func (s *BgpServer) DeleteStatement(ctx context.Context, r *api.DeleteStatementRequest) error {
	if r == nil || r.Statement == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		st, err := newStatementFromApiStruct(r.Statement)
		if err == nil {
			err = s.policy.DeleteStatement(st, r.All)
		}
		return err
	}, false)
}

func (s *BgpServer) ListPolicy(ctx context.Context, r *api.ListPolicyRequest, fn func(*api.Policy)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var l []*api.Policy
	s.mgmtOperation(func() error {
		pl := s.policy.GetPolicy(r.Name)
		l = make([]*api.Policy, 0, len(pl))
		for _, p := range pl {
			l = append(l, table.ToPolicyApi(p))
		}
		return nil
	}, false)
	for _, p := range l {
		select {
		case <-ctx.Done():
			return nil
		default:
			fn(p)
		}
	}
	return nil
}

func (s *BgpServer) AddPolicy(ctx context.Context, r *api.AddPolicyRequest) error {
	if r == nil || r.Policy == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		p, err := newPolicyFromApiStruct(r.Policy)
		if err == nil {
			err = s.policy.AddPolicy(p, r.ReferExistingStatements)
		}
		return err
	}, false)
}

func (s *BgpServer) DeletePolicy(ctx context.Context, r *api.DeletePolicyRequest) error {
	if r == nil || r.Policy == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		p, err := newPolicyFromApiStruct(r.Policy)
		if err != nil {
			return err
		}

		l := make([]string, 0, len(s.neighborMap)+1)
		for _, peer := range s.neighborMap {
			l = append(l, peer.ID())
		}
		l = append(l, table.GLOBAL_RIB_NAME)

		return s.policy.DeletePolicy(p, r.All, r.PreserveStatements, l)
	}, false)
}

func (s *BgpServer) toPolicyInfo(name string, dir api.PolicyDirection) (string, table.PolicyDirection, error) {
	if name == "" {
		return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("empty table name")
	}

	if name == table.GLOBAL_RIB_NAME {
		name = table.GLOBAL_RIB_NAME
	} else {
		peer, ok := s.neighborMap[name]
		if !ok {
			return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("not found peer %s", name)
		}
		if !peer.isRouteServerClient() {
			return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("non-rs-client peer %s doesn't have per peer policy", name)
		}
		name = peer.ID()
	}
	switch dir {
	case api.PolicyDirection_IMPORT:
		return name, table.POLICY_DIRECTION_IMPORT, nil
	case api.PolicyDirection_EXPORT:
		return name, table.POLICY_DIRECTION_EXPORT, nil
	}
	return "", table.POLICY_DIRECTION_NONE, fmt.Errorf("invalid policy type")
}

func (s *BgpServer) ListPolicyAssignment(ctx context.Context, r *api.ListPolicyAssignmentRequest, fn func(*api.PolicyAssignment)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var a []*api.PolicyAssignment
	err := s.mgmtOperation(func() error {
		names := make([]string, 0, len(s.neighborMap)+1)
		if r.Name == "" {
			names = append(names, table.GLOBAL_RIB_NAME)
			for name, peer := range s.neighborMap {
				if peer.isRouteServerClient() {
					names = append(names, name)
				}
			}
		} else {
			names = append(names, r.Name)
		}
		dirs := make([]api.PolicyDirection, 0, 2)
		if r.Direction == api.PolicyDirection_UNKNOWN {
			dirs = []api.PolicyDirection{api.PolicyDirection_EXPORT, api.PolicyDirection_IMPORT}
		} else {
			dirs = append(dirs, r.Direction)
		}

		a = make([]*api.PolicyAssignment, 0, len(names))
		for _, name := range names {
			for _, dir := range dirs {
				id, dir, err := s.toPolicyInfo(name, dir)
				if err != nil {
					return err
				}
				rt, policies, err := s.policy.GetPolicyAssignment(id, dir)
				if err != nil {
					return err
				}
				t := &table.PolicyAssignment{
					Name:     name,
					Type:     dir,
					Default:  rt,
					Policies: policies,
				}
				a = append(a, table.NewAPIPolicyAssignmentFromTableStruct(t))
			}
		}
		return nil
	}, false)
	if err == nil {
		for _, p := range a {
			select {
			case <-ctx.Done():
				return nil
			default:
				fn(p)
			}
		}
	}
	return err
}

func (s *BgpServer) AddPolicyAssignment(ctx context.Context, r *api.AddPolicyAssignmentRequest) error {
	if r == nil || r.Assignment == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		id, dir, err := s.toPolicyInfo(r.Assignment.Name, r.Assignment.Direction)
		if err != nil {
			return err
		}
		return s.policy.AddPolicyAssignment(id, dir, toPolicyDefinition(r.Assignment.Policies), defaultRouteType(r.Assignment.DefaultAction))
	}, false)
}

func (s *BgpServer) DeletePolicyAssignment(ctx context.Context, r *api.DeletePolicyAssignmentRequest) error {
	if r == nil || r.Assignment == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		id, dir, err := s.toPolicyInfo(r.Assignment.Name, r.Assignment.Direction)
		if err != nil {
			return err
		}
		return s.policy.DeletePolicyAssignment(id, dir, toPolicyDefinition(r.Assignment.Policies), r.All)
	}, false)
}

func (s *BgpServer) SetPolicyAssignment(ctx context.Context, r *api.SetPolicyAssignmentRequest) error {
	if r == nil || r.Assignment == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		id, dir, err := s.toPolicyInfo(r.Assignment.Name, r.Assignment.Direction)
		if err != nil {
			return err
		}
		return s.policy.SetPolicyAssignment(id, dir, toPolicyDefinition(r.Assignment.Policies), defaultRouteType(r.Assignment.DefaultAction))
	}, false)
}

func (s *BgpServer) EnableMrt(ctx context.Context, r *api.EnableMrtRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.mrtManager.enable(&config.MrtConfig{
			DumpInterval:     r.DumpInterval,
			RotationInterval: r.RotationInterval,
			DumpType:         config.IntToMrtTypeMap[int(r.Type)],
			FileName:         r.Filename,
		})
	}, false)
}

func (s *BgpServer) DisableMrt(ctx context.Context, r *api.DisableMrtRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.mrtManager.disable(&config.MrtConfig{})
	}, false)
}

func (s *BgpServer) ListRpki(ctx context.Context, r *api.ListRpkiRequest, fn func(*api.Rpki)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var l []*api.Rpki
	err := s.mgmtOperation(func() error {
		for _, r := range s.roaManager.GetServers() {
			received := &r.State.RpkiMessages.RpkiReceived
			sent := &r.State.RpkiMessages.RpkiSent
			rpki := &api.Rpki{
				Conf: &api.RPKIConf{
					Address:    r.Config.Address,
					RemotePort: uint32(r.Config.Port),
				},
				State: &api.RPKIState{
					Uptime:        config.ProtoTimestamp(r.State.Uptime),
					Downtime:      config.ProtoTimestamp(r.State.Downtime),
					Up:            r.State.Up,
					RecordIpv4:    r.State.RecordsV4,
					RecordIpv6:    r.State.RecordsV6,
					PrefixIpv4:    r.State.PrefixesV4,
					PrefixIpv6:    r.State.PrefixesV6,
					Serial:        r.State.SerialNumber,
					ReceivedIpv4:  received.Ipv4Prefix,
					ReceivedIpv6:  received.Ipv6Prefix,
					SerialNotify:  received.SerialNotify,
					CacheReset:    received.CacheReset,
					CacheResponse: received.CacheResponse,
					EndOfData:     received.EndOfData,
					Error:         received.Error,
					SerialQuery:   sent.SerialQuery,
					ResetQuery:    sent.ResetQuery,
				},
			}
			l = append(l, rpki)
		}
		return nil
	}, false)
	if err == nil {
		for _, r := range l {
			select {
			case <-ctx.Done():
				return nil
			default:
				fn(r)
			}
		}
	}
	return err
}

func (s *BgpServer) ListRpkiTable(ctx context.Context, r *api.ListRpkiTableRequest, fn func(*api.Roa)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	var l []*api.Roa
	err := s.mgmtOperation(func() error {
		family := bgp.RouteFamily(0)
		if r.Family != nil {
			family = bgp.AfiSafiToRouteFamily(uint16(r.Family.Afi), uint8(r.Family.Safi))
		}
		roas, err := s.roaTable.List(family)
		if err == nil {
			l = append(l, newRoaListFromTableStructList(roas)...)
		}
		return err
	}, false)
	if err == nil {
		for _, roa := range l {
			select {
			case <-ctx.Done():
				return nil
			default:
				fn(roa)
			}
		}
	}
	return err
}

func (s *BgpServer) AddRpki(ctx context.Context, r *api.AddRpkiRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.roaManager.AddServer(net.JoinHostPort(r.Address, strconv.Itoa(int(r.Port))), r.Lifetime)
	}, false)
}

func (s *BgpServer) DeleteRpki(ctx context.Context, r *api.DeleteRpkiRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.roaManager.DeleteServer(r.Address)
	}, false)
}

func (s *BgpServer) EnableRpki(ctx context.Context, r *api.EnableRpkiRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.roaManager.Enable(r.Address)
	}, false)
}

func (s *BgpServer) DisableRpki(ctx context.Context, r *api.DisableRpkiRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		return s.roaManager.Disable(r.Address)
	}, false)
}

func (s *BgpServer) ResetRpki(ctx context.Context, r *api.ResetRpkiRequest) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}
	return s.mgmtOperation(func() error {
		if r.Soft {
			return s.roaManager.SoftReset(r.Address)
		}
		return s.roaManager.Reset(r.Address)
	}, false)
}

func (s *BgpServer) WatchEvent(ctx context.Context, r *api.WatchEventRequest, fn func(*api.WatchEventResponse)) error {
	if r == nil {
		return fmt.Errorf("nil request")
	}

	opts := make([]watchOption, 0)
	if r.GetPeer() != nil {
		opts = append(opts, watchPeer())
	}
	if t := r.GetTable(); t != nil {
		for _, filter := range t.Filters {
			switch filter.Type {
			case api.WatchEventRequest_Table_Filter_BEST:
				opts = append(opts, watchBestPath(filter.Init))
			case api.WatchEventRequest_Table_Filter_ADJIN:
				opts = append(opts, watchUpdate(filter.Init, ""))
			case api.WatchEventRequest_Table_Filter_POST_POLICY:
				opts = append(opts, watchPostUpdate(filter.Init, ""))
			}
		}
	}
	if len(opts) == 0 {
		return fmt.Errorf("no events to watch")
	}
	w := s.watch(opts...)

	go func() {
		defer func() {
			w.Stop()
		}()

		for {
			select {
			case ev := <-w.Event():
				switch msg := ev.(type) {
				case *watchEventUpdate:
					paths := make([]*api.Path, 0)
					for _, path := range msg.PathList {
						paths = append(paths, toPathApi(path, nil, false, false))
					}

					fn(&api.WatchEventResponse{
						Event: &api.WatchEventResponse_Table{
							Table: &api.WatchEventResponse_TableEvent{
								Paths: paths,
							},
						},
					})
				case *watchEventBestPath:
					var pl []*api.Path
					if len(msg.MultiPathList) > 0 {
						l := make([]*table.Path, 0)
						for _, p := range msg.MultiPathList {
							l = append(l, p...)
						}
						for _, p := range l {
							pl = append(pl, toPathApi(p, nil, false, false))
						}
					} else {
						for _, p := range msg.PathList {
							pl = append(pl, toPathApi(p, nil, false, false))
						}
					}
					fn(&api.WatchEventResponse{
						Event: &api.WatchEventResponse_Table{
							Table: &api.WatchEventResponse_TableEvent{
								Paths: pl,
							},
						},
					})
				case *watchEventPeer:
					fn(&api.WatchEventResponse{
						Event: &api.WatchEventResponse_Peer{
							Peer: &api.WatchEventResponse_PeerEvent{
								Type: api.WatchEventResponse_PeerEvent_Type(msg.Type),
								Peer: &api.Peer{
									Conf: &api.PeerConf{
										PeerAsn:           msg.PeerAS,
										LocalAsn:          msg.LocalAS,
										NeighborAddress:   msg.PeerAddress.String(),
										NeighborInterface: msg.PeerInterface,
									},
									State: &api.PeerState{
										PeerAsn:         msg.PeerAS,
										LocalAsn:        msg.LocalAS,
										NeighborAddress: msg.PeerAddress.String(),
										SessionState:    api.PeerState_SessionState(int(msg.State) + 1),
										AdminState:      api.PeerState_AdminState(msg.AdminState),
										RouterId:        msg.PeerID.String(),
									},
									Transport: &api.Transport{
										LocalAddress: msg.LocalAddress.String(),
										LocalPort:    uint32(msg.LocalPort),
										RemotePort:   uint32(msg.PeerPort),
									},
								},
							},
						},
					})
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return nil
}

func (s *BgpServer) SetLogLevel(ctx context.Context, r *api.SetLogLevelRequest) error {
	oldLevel := uint32(s.logger.GetLevel())
	newLevel := uint32(r.Level)
	if oldLevel == newLevel {
		s.logger.Info("Logging level unchanged",
			log.Fields{
				"Topic":    "Config",
				"OldLevel": oldLevel})
	} else {
		s.logger.SetLevel(log.LogLevel(newLevel))
		s.logger.Info("Logging level changed",
			log.Fields{
				"Topic":    "Config",
				"OldLevel": oldLevel,
				"NewLevel": newLevel})
	}
	return nil
}

func (s *BgpServer) Log() log.Logger {
	return s.logger
}

type watchEventType string

const (
	watchEventTypeBestPath   watchEventType = "bestpath"
	watchEventTypePreUpdate  watchEventType = "preupdate"
	watchEventTypePostUpdate watchEventType = "postupdate"
	watchEventTypePeerState  watchEventType = "peerstate"
	watchEventTypeTable      watchEventType = "table"
	watchEventTypeRecvMsg    watchEventType = "receivedmessage"
)

type watchEvent interface {
}

type watchEventUpdate struct {
	Message      *bgp.BGPMessage
	PeerAS       uint32
	LocalAS      uint32
	PeerAddress  net.IP
	LocalAddress net.IP
	PeerID       net.IP
	FourBytesAs  bool
	Timestamp    time.Time
	Payload      []byte
	PostPolicy   bool
	Init         bool
	PathList     []*table.Path
	Neighbor     *config.Neighbor
}

type PeerEventType uint32

const (
	PEER_EVENT_UNKNOWN     PeerEventType = 0
	PEER_EVENT_INIT        PeerEventType = 1
	PEER_EVENT_END_OF_INIT PeerEventType = 2
	PEER_EVENT_STATE       PeerEventType = 3
)

type watchEventPeer struct {
	Type          PeerEventType
	PeerAS        uint32
	LocalAS       uint32
	PeerAddress   net.IP
	LocalAddress  net.IP
	PeerPort      uint16
	LocalPort     uint16
	PeerID        net.IP
	SentOpen      *bgp.BGPMessage
	RecvOpen      *bgp.BGPMessage
	State         bgp.FSMState
	OldState      bgp.FSMState
	StateReason   *fsmStateReason
	AdminState    adminState
	Timestamp     time.Time
	PeerInterface string
}

type watchEventAdjIn struct {
	PathList []*table.Path
}

type watchEventTable struct {
	RouterID string
	PathList map[string][]*table.Path
	Neighbor []*config.Neighbor
}

type watchEventBestPath struct {
	PathList      []*table.Path
	MultiPathList [][]*table.Path
	Vrf           map[uint32]bool
}

type watchEventMessage struct {
	Message      *bgp.BGPMessage
	PeerAS       uint32
	LocalAS      uint32
	PeerAddress  net.IP
	LocalAddress net.IP
	PeerID       net.IP
	FourBytesAs  bool
	Timestamp    time.Time
	IsSent       bool
}

type watchOptions struct {
	bestpath       bool
	preUpdate      bool
	postUpdate     bool
	peerState      bool
	initBest       bool
	initUpdate     bool
	initPostUpdate bool
	tableName      string
	recvMessage    bool
	peerAddress    string
}

type watchOption func(*watchOptions)

func watchBestPath(current bool) watchOption {
	return func(o *watchOptions) {
		o.bestpath = true
		if current {
			o.initBest = true
		}
	}
}

func watchUpdate(current bool, peerAddress string) watchOption {
	return func(o *watchOptions) {
		o.preUpdate = true
		if current {
			o.initUpdate = true
		}
		o.peerAddress = peerAddress
	}
}

func watchPostUpdate(current bool, peerAddress string) watchOption {
	return func(o *watchOptions) {
		o.postUpdate = true
		if current {
			o.initPostUpdate = true
		}
		o.peerAddress = peerAddress
	}
}

func watchPeer() watchOption {
	return func(o *watchOptions) {
		o.peerState = true
	}
}

func watchTableName(name string) watchOption {
	return func(o *watchOptions) {
		o.tableName = name
	}
}

func watchMessage(isSent bool) watchOption {
	return func(o *watchOptions) {
		if isSent {
			// log.WithFields(log.Fields{
			// 	"Topic": "Server",
			// }).Warn("watch event for sent messages is not implemented yet")
			// o.sentMessage = true
		} else {
			o.recvMessage = true
		}
	}
}

type watcher struct {
	opts   watchOptions
	realCh chan watchEvent
	ch     *channels.InfiniteChannel
	s      *BgpServer
}

func (w *watcher) Event() <-chan watchEvent {
	return w.realCh
}

func (w *watcher) Generate(t watchEventType) error {
	return w.s.mgmtOperation(func() error {
		switch t {
		case watchEventTypePreUpdate:
			pathList := make([]*table.Path, 0)
			for _, peer := range w.s.neighborMap {
				pathList = append(pathList, peer.adjRibIn.PathList(peer.configuredRFlist(), false)...)
			}
			w.notify(&watchEventAdjIn{PathList: clonePathList(pathList)})
		case watchEventTypeTable:
			rib := w.s.globalRib
			as := uint32(0)
			id := table.GLOBAL_RIB_NAME
			if len(w.opts.tableName) > 0 {
				peer, ok := w.s.neighborMap[w.opts.tableName]
				if !ok {
					return fmt.Errorf("neighbor that has %v doesn't exist", w.opts.tableName)
				}
				if !peer.isRouteServerClient() {
					return fmt.Errorf("neighbor %v doesn't have local rib", w.opts.tableName)
				}
				id = peer.ID()
				as = peer.AS()
				rib = w.s.rsRib
			}

			pathList := func() map[string][]*table.Path {
				pathList := make(map[string][]*table.Path)
				for _, t := range rib.Tables {
					for _, dst := range t.GetDestinations() {
						if paths := dst.GetKnownPathList(id, as); len(paths) > 0 {
							pathList[dst.GetNlri().String()] = clonePathList(paths)
						}
					}
				}
				return pathList
			}()
			l := make([]*config.Neighbor, 0, len(w.s.neighborMap))
			for _, peer := range w.s.neighborMap {
				l = append(l, w.s.toConfig(peer, false))
			}
			w.notify(&watchEventTable{PathList: pathList, Neighbor: l})
		default:
			return fmt.Errorf("unsupported type %v", t)
		}
		return nil
	}, false)
}

func (w *watcher) notify(v watchEvent) {
	w.ch.In() <- v
}

func (w *watcher) loop() {
	for ev := range w.ch.Out() {
		w.realCh <- ev.(watchEvent)
	}
	close(w.realCh)
}

func (w *watcher) Stop() {
	w.s.mgmtOperation(func() error {
		for k, l := range w.s.watcherMap {
			for i, v := range l {
				if w == v {
					w.s.watcherMap[k] = append(l[:i], l[i+1:]...)
					break
				}
			}
		}

		cleanInfiniteChannel(w.ch)
		// the loop function goroutine might be blocked for
		// writing to realCh. make sure it finishes.
		for range w.realCh {
		}
		return nil
	}, false)
}

func (s *BgpServer) isWatched(typ watchEventType) bool {
	return len(s.watcherMap[typ]) != 0
}

func (s *BgpServer) notifyWatcher(typ watchEventType, ev watchEvent) {
	for _, w := range s.watcherMap[typ] {
		w.notify(ev)
	}
}

func (s *BgpServer) watch(opts ...watchOption) (w *watcher) {
	s.mgmtOperation(func() error {
		w = &watcher{
			s:      s,
			realCh: make(chan watchEvent, 8),
			ch:     channels.NewInfiniteChannel(),
		}

		for _, opt := range opts {
			opt(&w.opts)
		}

		register := func(t watchEventType, w *watcher) {
			s.watcherMap[t] = append(s.watcherMap[t], w)
		}

		if w.opts.bestpath {
			register(watchEventTypeBestPath, w)
		}
		if w.opts.preUpdate {
			register(watchEventTypePreUpdate, w)
		}
		if w.opts.postUpdate {
			register(watchEventTypePostUpdate, w)
		}
		if w.opts.peerState {
			for _, p := range s.neighborMap {
				w.notify(newWatchEventPeer(p, nil, p.fsm.state, PEER_EVENT_INIT))
			}
			w.notify(&watchEventPeer{Type: PEER_EVENT_END_OF_INIT})

			register(watchEventTypePeerState, w)
		}

		if w.opts.initBest && s.active() == nil {
			w.notify(&watchEventBestPath{
				PathList:      s.globalRib.GetBestPathList(table.GLOBAL_RIB_NAME, 0, nil),
				MultiPathList: s.globalRib.GetBestMultiPathList(table.GLOBAL_RIB_NAME, nil),
			})
		}
		if w.opts.initUpdate {
			for _, peer := range s.neighborMap {
				peer.fsm.lock.RLock()
				notEstablished := peer.fsm.state != bgp.BGP_FSM_ESTABLISHED
				peerAddress := peer.fsm.peerInfo.Address.String()
				peer.fsm.lock.RUnlock()
				if notEstablished {
					continue
				}
				if len(w.opts.peerAddress) > 0 && w.opts.peerAddress != peerAddress {
					continue
				}
				configNeighbor := w.s.toConfig(peer, false)
				for _, rf := range peer.configuredRFlist() {
					peer.fsm.lock.RLock()
					_, y := peer.fsm.capMap[bgp.BGP_CAP_FOUR_OCTET_AS_NUMBER]
					l, _ := peer.fsm.LocalHostPort()
					update := &watchEventUpdate{
						PeerAS:       peer.fsm.peerInfo.AS,
						LocalAS:      peer.fsm.peerInfo.LocalAS,
						PeerAddress:  peer.fsm.peerInfo.Address,
						LocalAddress: net.ParseIP(l),
						PeerID:       peer.fsm.peerInfo.ID,
						FourBytesAs:  y,
						Init:         true,
						PostPolicy:   false,
						Neighbor:     configNeighbor,
						PathList:     peer.adjRibIn.PathList([]bgp.RouteFamily{rf}, false),
					}
					peer.fsm.lock.RUnlock()
					w.notify(update)

					eor := bgp.NewEndOfRib(rf)
					eorBuf, _ := eor.Serialize()
					peer.fsm.lock.RLock()
					update = &watchEventUpdate{
						Message:      eor,
						PeerAS:       peer.fsm.peerInfo.AS,
						LocalAS:      peer.fsm.peerInfo.LocalAS,
						PeerAddress:  peer.fsm.peerInfo.Address,
						LocalAddress: net.ParseIP(l),
						PeerID:       peer.fsm.peerInfo.ID,
						FourBytesAs:  y,
						Timestamp:    time.Now(),
						Init:         true,
						Payload:      eorBuf,
						PostPolicy:   false,
						Neighbor:     configNeighbor,
					}
					peer.fsm.lock.RUnlock()
					w.notify(update)
				}
			}
		}
		if w.opts.initPostUpdate && s.active() == nil {
			for _, rf := range s.globalRib.GetRFlist() {
				if len(s.globalRib.Tables[rf].GetDestinations()) == 0 {
					continue
				}
				pathsByPeer := make(map[*table.PeerInfo][]*table.Path)
				for _, path := range s.globalRib.GetPathList(table.GLOBAL_RIB_NAME, 0, []bgp.RouteFamily{rf}) {
					pathsByPeer[path.GetSource()] = append(pathsByPeer[path.GetSource()], path)
				}
				for peerInfo, paths := range pathsByPeer {
					// create copy which can be access to without mutex
					var configNeighbor *config.Neighbor
					peerAddress := peerInfo.Address.String()
					if peer, ok := s.neighborMap[peerAddress]; ok {
						configNeighbor = w.s.toConfig(peer, false)
					}
					if w.opts.peerAddress != "" && w.opts.peerAddress != peerAddress {
						continue
					}

					w.notify(&watchEventUpdate{
						PeerAS:      peerInfo.AS,
						PeerAddress: peerInfo.Address,
						PeerID:      peerInfo.ID,
						PostPolicy:  true,
						Neighbor:    configNeighbor,
						PathList:    paths,
						Init:        true,
					})

					eor := bgp.NewEndOfRib(rf)
					eorBuf, _ := eor.Serialize()
					w.notify(&watchEventUpdate{
						Message:     eor,
						PeerAS:      peerInfo.AS,
						PeerAddress: peerInfo.Address,
						PeerID:      peerInfo.ID,
						Timestamp:   time.Now(),
						Payload:     eorBuf,
						PostPolicy:  true,
						Neighbor:    configNeighbor,
						Init:        true,
					})
				}
			}
		}
		if w.opts.recvMessage {
			register(watchEventTypeRecvMsg, w)
		}

		go w.loop()
		return nil
	}, false)
	return w
}
