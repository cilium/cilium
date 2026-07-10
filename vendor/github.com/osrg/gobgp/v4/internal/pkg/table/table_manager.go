// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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

package table

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgryski/go-farm"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const (
	GLOBAL_RIB_NAME = "global"
)

func ProcessMessage(m *bgp.BGPMessage, peerInfo *PeerInfo, timestamp time.Time, treatAsWithdraw bool) []*Path {
	update := m.Body.(*bgp.BGPUpdate)

	if y, f := update.IsEndOfRib(); y {
		// this message has no normal updates or withdrawals.
		return []*Path{NewEOR(f)}
	}

	attrs := make([]bgp.PathAttributeInterface, 0, len(update.PathAttributes))
	var reach *bgp.PathAttributeMpReachNLRI
	var unreach *bgp.PathAttributeMpUnreachNLRI
	for _, attr := range update.PathAttributes {
		switch a := attr.(type) {
		case *bgp.PathAttributeMpReachNLRI:
			reach = a
		case *bgp.PathAttributeMpUnreachNLRI:
			unreach = a
		default:
			// update msg may not contain next_hop (type:3) in attr
			// due to it uses MpReachNLRI and it also has empty update.NLRI
			attrs = append(attrs, attr)
		}
	}

	if treatAsWithdraw {
		attrs = []bgp.PathAttributeInterface{}
	}

	var hash uint64
	if len(attrs) != 0 {
		total := bytes.NewBuffer(make([]byte, 0))
		for _, a := range attrs {
			b, _ := a.Serialize()
			total.Write(b)
		}
		hash = farm.Hash64(total.Bytes())
	}

	listLen := len(update.NLRI) + len(update.WithdrawnRoutes)
	if reach != nil {
		listLen += len(reach.Value)
	}
	if unreach != nil {
		listLen += len(unreach.Value)
	}

	pathList := make([]*Path, 0, listLen)

	for _, nlri := range update.NLRI {
		p := NewPath(bgp.RF_IPv4_UC, peerInfo, bgp.PathNLRI{NLRI: nlri.NLRI}, treatAsWithdraw, attrs, timestamp, false)
		p.remoteID = nlri.ID
		p.SetHash(hash)
		pathList = append(pathList, p)
	}

	if reach != nil {
		nexthop := reach.Nexthop
		family := bgp.NewFamily(reach.AFI, reach.SAFI)

		for _, nlri := range reach.Value {
			// when build path from reach
			// reachAttrs might not contain next_hop if `attrs` does not have one
			// this happens when a MP peer send update to gobgp
			// However nlri is always populated because how we build the path
			// path.info{nlri: nlri}
			// Compute a new attribute array for each path with one NLRI to make serialization
			// of path attrs faster
			reachAttrs := []bgp.PathAttributeInterface{}
			if !treatAsWithdraw {
				nlriAttr, _ := bgp.NewPathAttributeMpReachNLRI(family, []bgp.PathNLRI{nlri}, nexthop)
				reachAttrs = makeAttributeList(attrs, nlriAttr)
			}

			p := NewPath(family, peerInfo, bgp.PathNLRI{NLRI: nlri.NLRI}, treatAsWithdraw, reachAttrs, timestamp, false)
			p.remoteID = nlri.ID
			p.SetHash(hash)
			pathList = append(pathList, p)
		}
	}

	for _, nlri := range update.WithdrawnRoutes {
		p := NewPath(bgp.RF_IPv4_UC, peerInfo, bgp.PathNLRI{NLRI: nlri.NLRI}, true, []bgp.PathAttributeInterface{}, timestamp, false)
		p.remoteID = nlri.ID
		pathList = append(pathList, p)
	}

	if unreach != nil {
		family := bgp.NewFamily(unreach.AFI, unreach.SAFI)

		for _, nlri := range unreach.Value {
			p := NewPath(family, peerInfo, bgp.PathNLRI{NLRI: nlri.NLRI}, true, []bgp.PathAttributeInterface{}, timestamp, false)
			p.remoteID = nlri.ID
			pathList = append(pathList, p)
		}
	}

	return pathList
}

func makeAttributeList(
	attrs []bgp.PathAttributeInterface, reach *bgp.PathAttributeMpReachNLRI,
) []bgp.PathAttributeInterface {
	reachAttrs := make([]bgp.PathAttributeInterface, len(attrs)+1)
	copy(reachAttrs, attrs)
	// we sort attributes when creating a bgp message from paths
	reachAttrs[len(reachAttrs)-1] = reach
	return reachAttrs
}

type TableManager struct {
	mu             sync.RWMutex // protects tables and vrfs maps
	tables         map[bgp.Family]*Table
	vrfs           map[string]*Vrf
	rfList         []bgp.Family
	maxPathCounted atomic.Uint64
	logger         *slog.Logger
}

func NewTableManager(logger *slog.Logger, rfList []bgp.Family) *TableManager {
	t := &TableManager{
		mu:     sync.RWMutex{},
		tables: make(map[bgp.Family]*Table),
		vrfs:   make(map[string]*Vrf),
		rfList: rfList,
		logger: logger,
	}
	for _, rf := range rfList {
		t.tables[rf] = NewTable(logger, rf)
	}
	return t
}

// GetRFlist returns the list of routing families supported by the table manager.
// no lock is needed as rfList is not mutable, callers must treat the result as read-only.
func (manager *TableManager) GetRFlist() []bgp.Family {
	return manager.rfList
}

func (manager *TableManager) AddVrf(name string, id uint32, rd bgp.RouteDistinguisherInterface, importRt, exportRt []bgp.ExtendedCommunityInterface, info *PeerInfo) ([]*Path, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if _, ok := manager.vrfs[name]; ok {
		return nil, fmt.Errorf("vrf %s already exists", name)
	}
	rtMap, err := newRouteTargetMap(importRt)
	if err != nil {
		return nil, err
	}
	manager.logger.Debug("add vrf",
		slog.String("Topic", "Vrf"),
		slog.String("Key", name),
		slog.String("Rd", rd.String()),
		slog.Any("ImportRt", rtMap.ToSlice()),
		slog.Any("ExportRt", exportRt),
	)
	manager.vrfs[name] = &Vrf{
		Name:     name,
		Id:       id,
		Rd:       rd,
		ImportRt: rtMap,
		ExportRt: exportRt,
	}
	msgs := make([]*Path, 0, len(importRt))
	nexthop := netip.IPv4Unspecified()
	for _, target := range importRt {
		nlri := bgp.NewRouteTargetMembershipNLRI(info.AS, target)
		pattr := make([]bgp.PathAttributeInterface, 0, 2)
		pattr = append(pattr, bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP))
		attr, _ := bgp.NewPathAttributeMpReachNLRI(bgp.RF_RTC_UC, []bgp.PathNLRI{{NLRI: nlri}}, nexthop)
		pattr = append(pattr, attr)
		msgs = append(msgs, NewPath(bgp.RF_RTC_UC, info, bgp.PathNLRI{NLRI: nlri}, false, pattr, time.Now(), false))
	}
	return msgs, nil
}

func (manager *TableManager) DeleteVrf(name string) ([]*Path, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	if _, ok := manager.vrfs[name]; !ok {
		return nil, fmt.Errorf("vrf %s not found", name)
	}
	msgs := make([]*Path, 0)
	vrf := manager.vrfs[name]
	for _, t := range manager.tables {
		msgs = append(msgs, t.deletePathsByVrf(vrf)...)
	}
	manager.logger.Debug("delete vrf",
		slog.String("Topic", "Vrf"),
		slog.String("Key", vrf.Name),
		slog.String("Rd", vrf.Rd.String()),
		slog.Any("ImportRt", vrf.ImportRt.ToSlice()),
		slog.Any("ExportRt", vrf.ExportRt),
		slog.Any("MplsLabel", vrf.MplsLabel),
	)
	delete(manager.vrfs, name)
	rtcTable := manager.tables[bgp.RF_RTC_UC]
	msgs = append(msgs, rtcTable.deleteRTCPathsByVrf(vrf, manager.vrfs)...)
	return msgs, nil
}

func (manager *TableManager) Update(newPath *Path) []*Update {
	if newPath == nil || newPath.IsEOR() {
		return nil
	}

	// Except for a special case with EVPN, we'll have one destination.
	updates := make([]*Update, 0, 1)
	family := newPath.GetFamily()

	manager.mu.RLock()
	defer manager.mu.RUnlock()

	table, ok := manager.tables[family]
	if !ok {
		return updates
	}

	updates = append(updates, table.update(newPath))
	if family == bgp.RF_EVPN {
		for _, p := range manager.handleMacMobility(newPath) {
			updates = append(updates, table.update(p))
		}
	}
	return updates
}

// EVPN MAC MOBILITY HANDLING
//
// RFC7432 15. MAC Mobility
//
// A PE receiving a MAC/IP Advertisement route for a MAC address with a
// different Ethernet segment identifier and a higher sequence number
// than that which it had previously advertised withdraws its MAC/IP
// Advertisement route.
// ......
// If the PE is the originator of the MAC route and it receives the same
// MAC address with the same sequence number that it generated, it will
// compare its own IP address with the IP address of the remote PE and
// will select the lowest IP.  If its own route is not the best one, it
// will withdraw the route.
func (manager *TableManager) handleMacMobility(path *Path) []*Path {
	pathList := make([]*Path, 0)
	nlri := path.GetNlri().(*bgp.EVPNNLRI)
	if path.IsWithdraw || path.IsLocal() || nlri.RouteType != bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT {
		return nil
	}

	f := func(p *Path) (bgp.EthernetSegmentIdentifier, uint32, net.HardwareAddr, int, netip.Addr) {
		nlri := p.GetNlri().(*bgp.EVPNNLRI)
		d := nlri.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
		ecs := p.GetExtCommunities()
		seq := -1
		for _, ec := range ecs {
			if t, st := ec.GetTypes(); t == bgp.EC_TYPE_EVPN && st == bgp.EC_SUBTYPE_MAC_MOBILITY {
				seq = int(ec.(*bgp.MacMobilityExtended).Sequence)
				break
			}
		}
		return d.ESI, d.ETag, d.MacAddress, seq, p.GetSource().Address
	}
	e1, et1, m1, s1, i1 := f(path)

	// Extract the route targets to scope the lookup to the MAC-VRF with the MAC address.
	// This will help large EVPN instances where a single MAC is present in a lot of MAC-VRFs (e.g.
	// an anycast router).
	// A route may have multiple route targets, to target multiple MAC-VRFs (e.g. in both an L2VNI
	// and L3VNI in the VXLAN case).
	var paths []*Path
	for _, ec := range path.GetRouteTargets() {
		paths = append(paths, manager.GetPathListWithMac(GLOBAL_RIB_NAME, 0, []bgp.Family{bgp.RF_EVPN}, ec, m1)...)
	}

	for _, path2 := range paths {
		if !path2.IsLocal() || path2.GetNlri().(*bgp.EVPNNLRI).RouteType != bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT {
			continue
		}
		e2, et2, m2, s2, i2 := f(path2)
		if et1 == et2 && bytes.Equal(m1, m2) && !bytes.Equal(e1.Value, e2.Value) {
			if s1 > s2 || s1 == s2 && i1.Compare(i2) < 0 {
				pathList = append(pathList, path2.Clone(true))
			}
		}
	}
	return pathList
}

// getTables returns the list of tables for the given routing families.
// must be called under read lock
func (manager *TableManager) getTables(list ...bgp.Family) []*Table {
	l := make([]*Table, 0, len(manager.tables))
	if len(list) == 0 {
		for _, v := range manager.tables {
			l = append(l, v)
		}
		return l
	}
	for _, f := range list {
		if t, ok := manager.tables[f]; ok {
			l = append(l, t)
		}
	}
	return l
}

// updateMaxPathCounted updates the estimated maximum number of paths counted.
func (manager *TableManager) updateMaxPathCounted(pathCount int) {
	count := manager.maxPathCounted.Load()
	if count < uint64(pathCount) {
		manager.maxPathCounted.Store(uint64(pathCount))
		return
	}
	// save half of the last maximum counted number of paths as the new limit
	// to avoid unlimited maximum path count growth for life time of the process
	if uint64(pathCount) < count/2 {
		manager.maxPathCounted.Store(count / 2)
		return
	}
}

// GetPathsByRT returns all paths indexed under rt across all tables in rfList.
// If rt is nil, returns nil.
// Only tables with a VPNPathIndex (VPN, EVPN, …) contribute results.
func (manager *TableManager) GetPathsByRT(rt bgp.ExtendedCommunityInterface, rfList []bgp.Family) []*Path {
	if rt == nil {
		return nil
	}
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	var paths []*Path
	for _, t := range manager.getTables(rfList...) {
		if idx := t.GetVPNIndex(); idx != nil {
			paths = append(paths, idx.GetPathsByRT(rt)...)
		}
	}
	return paths
}

func (manager *TableManager) GetBestPathList(id string, as uint32, rfList []bgp.Family) []*Path {
	if SelectionOptions.DisableBestPathSelection {
		// Note: If best path selection disabled, there is no best path.
		return nil
	}

	manager.mu.RLock()
	defer manager.mu.RUnlock()

	paths := make([]*Path, 0, manager.maxPathCounted.Load())
	for _, t := range manager.getTables(rfList...) {
		paths = append(paths, t.Bests(id, as)...)
	}
	manager.updateMaxPathCounted(len(paths))
	return paths
}

func (manager *TableManager) GetBestMultiPathList(id string, rfList []bgp.Family) [][]*Path {
	if !UseMultiplePaths.Enabled || SelectionOptions.DisableBestPathSelection {
		// Note: If multi path not enabled or best path selection disabled,
		// there is no best multi path.
		return nil
	}

	manager.mu.RLock()
	defer manager.mu.RUnlock()

	paths := make([][]*Path, 0, manager.maxPathCounted.Load())
	for _, t := range manager.getTables(rfList...) {
		paths = append(paths, t.MultiBests(id)...)
	}
	manager.updateMaxPathCounted(len(paths))
	return paths
}

func (manager *TableManager) GetPathList(id string, as uint32, rfList []bgp.Family) []*Path {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	paths := make([]*Path, 0, manager.maxPathCounted.Load())
	for _, t := range manager.getTables(rfList...) {
		paths = append(paths, t.GetKnownPathList(id, as)...)
	}
	manager.updateMaxPathCounted(len(paths))
	return paths
}

func (manager *TableManager) GetPathListWithMac(id string, as uint32, rfList []bgp.Family, rt bgp.ExtendedCommunityInterface, mac net.HardwareAddr) []*Path {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	paths := make([]*Path, 0, manager.maxPathCounted.Load())
	for _, t := range manager.getTables(rfList...) {
		paths = append(paths, t.GetKnownPathListWithMac(id, as, rt, mac, false)...)
	}
	manager.updateMaxPathCounted(len(paths))
	return paths
}

func (manager *TableManager) GetPathListWithNexthop(id string, rfList []bgp.Family, nexthop netip.Addr) []*Path {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	paths := make([]*Path, 0, manager.maxPathCounted.Load())
	for _, rf := range rfList {
		if t, ok := manager.tables[rf]; ok {
			for _, path := range t.GetKnownPathList(id, 0) {
				if path.GetNexthop() == nexthop {
					paths = append(paths, path)
				}
			}
		}
	}
	manager.updateMaxPathCounted(len(paths))
	return paths
}

func (manager *TableManager) GetPathListWithSource(id string, rfList []bgp.Family, source *PeerInfo) []*Path {
	manager.mu.RLock()
	defer manager.mu.RUnlock()

	paths := make([]*Path, 0, manager.maxPathCounted.Load())
	for _, rf := range rfList {
		if t, ok := manager.tables[rf]; ok {
			for _, path := range t.GetKnownPathList(id, 0) {
				if path.GetSource().Equal(source) {
					paths = append(paths, path)
				}
			}
		}
	}
	manager.updateMaxPathCounted(len(paths))
	return paths
}

func (manager *TableManager) GetDestination(path *Path) *destination {
	if path == nil {
		return nil
	}
	family := path.GetFamily()

	manager.mu.RLock()
	defer manager.mu.RUnlock()

	t, ok := manager.tables[family]
	if !ok {
		return nil
	}
	return t.GetDestination(path.GetNlri())
}

// GetTable returns the routing table for the given address family.
// Thread-safe: uses RLock internally.
func (manager *TableManager) GetTable(family bgp.Family) (*Table, bool) {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	tbl, ok := manager.tables[family]
	return tbl, ok
}

// SetTable sets the routing table for the given address family.
// Thread-safe: uses Lock internally.
func (manager *TableManager) SetTable(family bgp.Family, tbl *Table) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	manager.tables[family] = tbl
}

// GetVrf returns the VRF with the given name.
// Thread-safe: uses RLock internally.
func (manager *TableManager) GetVrf(name string) (*Vrf, bool) {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	vrf, ok := manager.vrfs[name]
	return vrf, ok
}

// GetAllVrfs returns a copy of all VRF names.
// Thread-safe: uses RLock internally.
func (manager *TableManager) GetAllVrfs() []string {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	names := make([]string, 0, len(manager.vrfs))
	for name := range manager.vrfs {
		names = append(names, name)
	}
	return names
}

// GetAllVrfsMap returns a shallow copy of the VRFs map.
// Thread-safe: uses RLock internally.
// Note: The Vrf objects themselves are shared, so callers should not modify them.
func (manager *TableManager) GetAllVrfsMap() map[string]*Vrf {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	vrfs := make(map[string]*Vrf, len(manager.vrfs))
	for name, vrf := range manager.vrfs {
		vrfs[name] = vrf
	}
	return vrfs
}

// GetAllTablesMap returns a shallow copy of the routing tables map.
// Thread-safe: uses RLock internally.
// Note: The Table objects themselves are shared, so callers should not modify them.
func (manager *TableManager) GetAllTablesMap() map[bgp.Family]*Table {
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	tables := make(map[bgp.Family]*Table, len(manager.tables))
	for family, tbl := range manager.tables {
		tables[family] = tbl
	}
	return tables
}
