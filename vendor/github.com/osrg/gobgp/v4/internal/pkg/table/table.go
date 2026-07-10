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
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"math/bits"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/gaissmai/bart"
	"github.com/segmentio/fasthash/fnv1a"

	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func addrPrefixOnlySerialize(nlri bgp.NLRI) []byte {
	switch T := nlri.(type) {
	case *bgp.IPAddrPrefix:
		byteLen := T.Prefix.Addr().BitLen() / 8
		b := make([]byte, byteLen+1)
		copy(b, T.Prefix.Addr().AsSlice())
		b[byteLen] = uint8(T.Prefix.Bits())
		return b
	case *bgp.LabeledVPNIPAddrPrefix:
		byteLen := T.Prefix.Addr().BitLen() / 8
		// RD and length
		b := make([]byte, byteLen+9)
		serializedRD, _ := T.RD.Serialize()
		copy(b, serializedRD)
		copy(b[8:], T.Prefix.Addr().AsSlice())
		b[8+byteLen] = uint8(T.Prefix.Bits())
		return b
	}
	return []byte(nlri.String())
}

func AddrPrefixOnlyCompare(a, b bgp.NLRI) int {
	return bytes.Compare(addrPrefixOnlySerialize(a), addrPrefixOnlySerialize(b))
}

// used internally, should not be aliassed
type (
	addrPrefixKey uint64
	macKey        uint64
)

type TableSelectOption struct {
	ID             string
	AS             uint32
	LookupPrefixes []*apiutil.LookupPrefix
	VRF            *Vrf
	adj            bool
	Best           bool
	MultiPath      bool
}

func tableKey(nlri bgp.NLRI) addrPrefixKey {
	h := fnv1a.Init64
	switch T := nlri.(type) {
	case *bgp.IPAddrPrefix:
		h = fnv1a.AddBytes64(h, T.Prefix.Addr().AsSlice())
		h = fnv1a.AddBytes64(h, []byte{uint8(T.Prefix.Bits())})
	case *bgp.LabeledVPNIPAddrPrefix:
		serializedRD, _ := T.RD.Serialize()
		h = fnv1a.AddBytes64(h, serializedRD)
		h = fnv1a.AddBytes64(h, T.Prefix.Addr().AsSlice())
		h = fnv1a.AddBytes64(h, []byte{uint8(T.Prefix.Bits())})
	default:
		h = fnv1a.AddString64(h, nlri.String())
	}
	return addrPrefixKey(h)
}

// destinationShard is a sharded bucket that owns both the map subset and the lock
// that protects both map operations and destination data within this shard.
type destinationShard struct {
	mu *sync.RWMutex
	mp map[addrPrefixKey][]*destination
}

const destinationShardCount = 2048

type Destinations struct {
	shards [destinationShardCount]*destinationShard
}

func NewDestinations() *Destinations {
	d := &Destinations{}
	for i := range d.shards {
		d.shards[i] = &destinationShard{
			mu: &sync.RWMutex{},
			mp: make(map[addrPrefixKey][]*destination),
		}
	}
	return d
}

// getShard returns the shard for a given NLRI
func (d *Destinations) getShard(nlri bgp.NLRI) *destinationShard {
	key := tableKey(nlri)
	return d.shards[uint32(key)&(destinationShardCount-1)]
}

// iterateAllDestinations calls fn for each destination across all shards.
// Rlock will be hold per shard during the call of fn callback.
func (d *Destinations) iterateAllDestinations(fn func(*destination)) {
	for _, shard := range d.shards {
		shard.mu.RLock()
		for _, dests := range shard.mp {
			for _, dest := range dests {
				fn(dest)
			}
		}
		shard.mu.RUnlock()
	}
}

func (d *Destinations) Get(nlri bgp.NLRI) *destination {
	shard := d.getShard(nlri)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	key := tableKey(nlri)
	dests, ok := shard.mp[key]
	if !ok {
		return nil
	}

	for _, dest := range dests {
		if AddrPrefixOnlyCompare(dest.nlri, nlri) == 0 {
			return dest.snapshot()
		}
	}
	return nil
}

func (d *Destinations) InsertUpdate(dest *destination) (collision bool) {
	shard := d.getShard(dest.nlri)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	nlri := dest.nlri
	key := tableKey(nlri)
	new := false
	if _, ok := shard.mp[key]; !ok {
		shard.mp[key] = make([]*destination, 0)
		new = true
	}
	for i, v := range shard.mp[key] {
		if AddrPrefixOnlyCompare(v.nlri, nlri) == 0 {
			shard.mp[key][i] = dest
			return collision
		}
	}
	if !new {
		// we have collision
		collision = true
	}
	shard.mp[key] = append(shard.mp[key], dest)
	return collision
}

func macKeyHash(rt bgp.ExtendedCommunityInterface, mac net.HardwareAddr) macKey {
	b, _ := rt.Serialize()
	b = append(b, mac...)
	return macKey(fnv1a.HashBytes64(b))
}

type EVPNMacNLRIs struct {
	mp map[macKey]map[*destination]struct{}
	mu *sync.RWMutex
}

func NewEVPNMacNLRIs() *EVPNMacNLRIs {
	return &EVPNMacNLRIs{mp: make(map[macKey]map[*destination]struct{}), mu: &sync.RWMutex{}}
}

func (e *EVPNMacNLRIs) Get(rt bgp.ExtendedCommunityInterface, mac net.HardwareAddr) (d []*destination) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if dests, ok := e.mp[macKeyHash(rt, mac)]; ok {
		d = make([]*destination, len(dests))
		i := 0
		for dest := range dests {
			d[i] = dest
			i++
		}
	}
	return d
}

func (e *EVPNMacNLRIs) Insert(rt bgp.ExtendedCommunityInterface, mac net.HardwareAddr, dest *destination) {
	e.mu.Lock()
	defer e.mu.Unlock()

	macKey := macKeyHash(rt, mac)
	if _, ok := e.mp[macKey]; !ok {
		e.mp[macKey] = make(map[*destination]struct{})
	}
	e.mp[macKey][dest] = struct{}{}
}

func (e *EVPNMacNLRIs) Remove(rt bgp.ExtendedCommunityInterface, mac net.HardwareAddr, dest *destination) {
	e.mu.Lock()
	defer e.mu.Unlock()

	macKey := macKeyHash(rt, mac)
	if dests, ok := e.mp[macKey]; ok {
		delete(dests, dest)
		if len(dests) == 0 {
			delete(e.mp, macKey)
		}
	}
}

type Table struct {
	Family       bgp.Family
	destinations *Destinations
	logger       *slog.Logger
	// index of evpn prefixes with paths to a specific MAC in a MAC-VRF
	// this is a map[rt, MAC address]map[addrPrefixKey][]nlri
	// this holds a map for a set of prefixes.
	macIndex *EVPNMacNLRIs
	// vpnIdx indexes all known paths by Route Target for O(1) RT-based lookup.
	// Non-nil only for families that carry RT extended communities (VPNV4-6, EVPN, …).
	vpnIdx *VPNPathIndex
}

// vpnFamilies lists the route families whose paths carry RT extended communities
// and should therefore be indexed in VPNPathIndex.
func isVPNFamily(rf bgp.Family) bool {
	switch rf {
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN,
		bgp.RF_IPv4_VPN_MC, bgp.RF_IPv6_VPN_MC,
		bgp.RF_EVPN,
		bgp.RF_FS_IPv4_VPN, bgp.RF_FS_IPv6_VPN,
		bgp.RF_MUP_IPv4, bgp.RF_MUP_IPv6:
		return true
	}
	return false
}

func NewTable(logger *slog.Logger, rf bgp.Family, dsts ...*destination) *Table {
	var vpnIdx *VPNPathIndex
	if isVPNFamily(rf) {
		vpnIdx = NewVPNPathIndex()
	}
	t := &Table{
		Family:       rf,
		destinations: NewDestinations(),
		logger:       logger,
		macIndex:     NewEVPNMacNLRIs(),
		vpnIdx:       vpnIdx,
	}
	for _, dst := range dsts {
		t.setDestination(dst)
	}
	return t
}

// GetVPNIndex returns the RT-keyed path index for this table, or nil if the
// table's family does not carry RT extended communities.
func (t *Table) GetVPNIndex() *VPNPathIndex {
	return t.vpnIdx
}

func (t *Table) GetFamily() bgp.Family {
	return t.Family
}

func (t *Table) deletePathsByVrf(vrf *Vrf) []*Path {
	// Early return for families that don't support VRF (no RD in NLRI)
	switch t.Family {
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN, bgp.RF_IPv4_VPN_MC, bgp.RF_IPv6_VPN_MC,
		bgp.RF_EVPN, bgp.RF_MUP_IPv4, bgp.RF_MUP_IPv6:
		// These families have RD in their NLRI, continue
	default:
		// Non-VPN family, no paths belong to any VRF
		return nil
	}

	pathList := make([]*Path, 0)
	t.destinations.iterateAllDestinations(func(dest *destination) {
		for _, p := range dest.knownPathList {
			var rd bgp.RouteDistinguisherInterface
			nlri := p.GetNlri()
			switch v := nlri.(type) {
			case *bgp.LabeledVPNIPAddrPrefix:
				rd = v.RD
			case *bgp.EVPNNLRI:
				rd = v.RD()
			case *bgp.MUPNLRI:
				rd = v.RD()
			default:
				return
			}
			if p.IsLocal() && vrf.Rd.String() == rd.String() {
				pathList = append(pathList, p.Clone(true))
				return
			}
		}
	})
	return pathList
}

func (t *Table) deleteRTCPathsByVrf(vrf *Vrf, vrfs map[string]*Vrf) []*Path {
	pathList := make([]*Path, 0)
	if t.Family != bgp.RF_RTC_UC {
		return pathList
	}
	for lhs := range vrf.ImportRt {
		t.destinations.iterateAllDestinations(func(dest *destination) {
			nlri := dest.GetNlri().(*bgp.RouteTargetMembershipNLRI)
			rhs, _ := extCommRouteTargetKey(nlri.RouteTarget)
			if lhs == rhs && isLastTargetUser(vrfs, lhs) {
				for _, p := range dest.knownPathList {
					if p.IsLocal() {
						pathList = append(pathList, p.Clone(true))
						return
					}
				}
			}
		})
	}
	return pathList
}

func (t *Table) validatePath(path *Path) {
	if path == nil {
		t.logger.Error("path is nil",
			slog.String("Topic", "Table"),
			slog.String("Key", t.Family.String()),
		)
	}
	if path.GetFamily() != t.Family {
		t.logger.Error("Invalid path. Family mismatch",
			slog.String("Topic", "Table"),
			slog.String("Key", t.Family.String()),
			slog.Any("Prefix", path.GetPrefix()),
			slog.String("ReceivedRf", path.GetFamily().String()),
		)
	}
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH); attr != nil {
		pathParam := attr.(*bgp.PathAttributeAsPath).Value
		for _, as := range pathParam {
			_, y := as.(*bgp.As4PathParam)
			if !y {
				t.logger.Error("AsPathParam must be converted to As4PathParam",
					slog.String("Topic", "Table"),
					slog.String("Key", t.Family.String()),
					slog.Any("As", as),
				)
			}
		}
	}
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS4_PATH); attr != nil {
		t.logger.Error("AS4_PATH must be converted to AS_PATH",
			slog.String("Topic", "Table"),
			slog.String("Key", t.Family.String()),
		)
	}
	if path.GetNlri() == nil {
		t.logger.Error("path's nlri is nil",
			slog.String("Topic", "Table"),
			slog.String("Key", t.Family.String()),
		)
	}
}

// getOrCreateDest gets or creates a destination while holding the shard lock.
// Caller must hold the shard lock before calling this.
func (t *Table) getOrCreateDest(shard *destinationShard, nlri bgp.NLRI, size int) *destination {
	key := tableKey(nlri)

	// Check if destination already exists
	if dests, ok := shard.mp[key]; ok {
		for _, dest := range dests {
			if AddrPrefixOnlyCompare(dest.nlri, nlri) == 0 {
				return dest
			}
		}
	}

	// Create and insert new destination
	dest := newDestination(nlri, size)
	if _, ok := shard.mp[key]; !ok {
		shard.mp[key] = make([]*destination, 0)
	}
	shard.mp[key] = append(shard.mp[key], dest)
	return dest
}

// deleteDest removes a destination from the shard.
// Caller must hold the shard lock before calling this.
func (t *Table) deleteDest(shard *destinationShard, dest *destination) {
	count := 0
	for _, v := range dest.localIdMap.bitmap {
		count += bits.OnesCount64(v)
	}
	if len(dest.localIdMap.bitmap) != 0 && count != 1 {
		return
	}

	nlri := dest.GetNlri()
	key := tableKey(nlri)
	if _, ok := shard.mp[key]; !ok {
		return
	}
	for i, v := range shard.mp[key] {
		if AddrPrefixOnlyCompare(v.nlri, nlri) == 0 {
			shard.mp[key] = append(shard.mp[key][:i], shard.mp[key][i+1:]...)
			if len(shard.mp[key]) == 0 {
				delete(shard.mp, key)
			}
			break
		}
	}

	// Clean up EVPN mac index
	if evpnNlri, ok := nlri.(*bgp.EVPNNLRI); ok {
		if macadv, ok := evpnNlri.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute); ok {
			for _, path := range dest.knownPathList {
				for _, ec := range path.GetRouteTargets() {
					t.macIndex.Remove(ec, macadv.MacAddress, dest)
				}
			}
		}
	}
}

func (t *Table) update(newPath *Path) *Update {
	t.validatePath(newPath)

	nlri := newPath.GetNlri()
	shard := t.destinations.getShard(nlri)

	// Hold shard lock for entire operation - no TOCTOU gap
	shard.mu.Lock()
	defer shard.mu.Unlock()

	dst := t.getOrCreateDest(shard, nlri, 64)
	u, oldPath := dst.Calculate(t.logger, newPath)

	if len(dst.knownPathList) == 0 {
		t.deleteDest(shard, dst)
	}

	if evpnNlri, ok := nlri.(*bgp.EVPNNLRI); ok {
		if macadv, ok := evpnNlri.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute); ok {
			for _, ec := range newPath.GetRouteTargets() {
				t.macIndex.Insert(ec, macadv.MacAddress, dst)
			}
		}
	}

	t.updateVPNIdx(u, newPath, oldPath)
	return u
}

// updateVPNIdx keeps the vpnIdx in sync with the VPN path table after each
// update. It must be called immediately after dst.Calculate so that
// OldKnownPathList and KnownPathList reflect the state before and after the
// change respectively.
func (t *Table) updateVPNIdx(u *Update, newPath, oldPath *Path) {
	if t.vpnIdx == nil {
		return
	}
	if newPath.RemoteID() != 0 {
		// ADD-PATH: each (source, path-ID) pair is a distinct entry.
		// oldPath is the previous path with the same source×pathID returned by
		// implicitWithdraw (non-withdrawal) or explicitWithdraw (withdrawal).
		if newPath.IsWithdraw {
			t.vpnIdx.UnregisterPath(oldPath)
		} else {
			t.vpnIdx.UnregisterPath(oldPath)
			t.vpnIdx.RegisterPath(newPath)
		}
		return
	}
	// No-add-path: track only the best path per NLRI.
	// KnownPathList is sorted by computeKnownBestPath, so [0] is the best.
	var oldBest, newBest *Path
	if len(u.OldKnownPathList) > 0 {
		oldBest = u.OldKnownPathList[0]
	}
	if len(u.KnownPathList) > 0 {
		newBest = u.KnownPathList[0]
	}
	if oldBest != newBest {
		t.vpnIdx.UnregisterPath(oldBest)
		t.vpnIdx.RegisterPath(newBest)
	}
}

// GetDestinations returns snapshots of all destinations in the table.
// The snapshots are created while holding shard lock, then the locks are released.
// The returned snapshots can be safely used without holding locks.
// This is safe for iteration but may be expensive for large tables.
func (t *Table) GetDestinations() []*destination {
	destinations := make([]*destination, 0)
	t.destinations.iterateAllDestinations(func(dest *destination) {
		destinations = append(destinations, dest.snapshot())
	})
	return destinations
}

// GetDestination returns a snapshot of the destination for the given NLRI.
// The snapshot can be safely used without holding locks.
// Returns nil if the destination doesn't exist.
func (t *Table) GetDestination(nlri bgp.NLRI) *destination {
	return t.destinations.Get(nlri)
}

// SelectDestination returns a selected/filtered destination for the given NLRI,
// This is a Table-level locked helper that ensures destination methods are called
// with the shard read lock held, preventing races on active destinations.
// Returns nil if the destination doesn't exist or selection produces no paths.
//
// Use this instead of GetDestination() + Select() when you need to select a single
// destination and want the locking to be encapsulated in a single call.
// The shard read lock is held while calling destination.Select().
func (t *Table) SelectDestination(nlri bgp.NLRI, option DestinationSelectOption) *destination {
	shard := t.destinations.getShard(nlri)
	shard.mu.RLock()
	defer shard.mu.RUnlock()

	key := tableKey(nlri)
	dests, ok := shard.mp[key]
	if !ok {
		return nil
	}

	for _, dest := range dests {
		if AddrPrefixOnlyCompare(dest.nlri, nlri) == 0 {
			// Call Select while holding lock, which returns a new destination
			return dest.Select(option)
		}
	}
	return nil
}

func (t *Table) GetLongerPrefixDestinations(key string) ([]*destination, error) {
	destinations := t.GetDestinations()
	results := make([]*destination, 0, len(destinations))
	switch t.Family {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC, bgp.RF_IPv4_MPLS, bgp.RF_IPv6_MPLS:
		prefix, err := netip.ParsePrefix(key)
		if err != nil {
			return nil, fmt.Errorf("error parsing cidr %s: %v", key, err)
		}

		r := new(bart.Table[*destination])
		for _, dst := range t.GetDestinations() {
			r.Insert(nlriToPrefix(dst.nlri), dst)
		}
		for _, d := range r.Subnets(prefix) {
			results = append(results, d)
		}
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		prefixRd, prefix, err := bgp.ParseVPNPrefix(key)
		if err != nil {
			return nil, err
		}

		r := new(bart.Table[*destination])
		for _, dst := range t.GetDestinations() {
			dstRD := dst.nlri.(*bgp.LabeledVPNIPAddrPrefix).RD
			if prefixRd.String() != dstRD.String() {
				continue
			}

			r.Insert(nlriToPrefix(dst.nlri), dst)
		}
		for _, d := range r.Subnets(prefix) {
			results = append(results, d)
		}
	default:
		results = append(results, t.GetDestinations()...)
	}
	return results, nil
}

func (t *Table) GetEvpnDestinationsWithRouteType(typ string) ([]*destination, error) {
	var routeType uint8
	switch strings.ToLower(typ) {
	case "a-d":
		routeType = bgp.EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY
	case "macadv":
		routeType = bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT
	case "multicast":
		routeType = bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG
	case "esi":
		routeType = bgp.EVPN_ETHERNET_SEGMENT_ROUTE
	case "prefix":
		routeType = bgp.EVPN_IP_PREFIX
	default:
		return nil, fmt.Errorf("unsupported evpn route type: %s", typ)
	}
	destinations := t.GetDestinations()
	results := make([]*destination, 0, len(destinations))
	switch t.Family {
	case bgp.RF_EVPN:
		for _, dst := range destinations {
			if nlri, ok := dst.nlri.(*bgp.EVPNNLRI); !ok {
				return nil, fmt.Errorf("invalid evpn nlri type detected: %T", dst.nlri)
			} else if nlri.RouteType == routeType {
				results = append(results, dst)
			}
		}
	default:
		results = append(results, destinations...)
	}
	return results, nil
}

func (t *Table) GetMUPDestinationsWithRouteType(p string) ([]*destination, error) {
	var routeType uint16
	switch strings.ToLower(p) {
	case "isd":
		routeType = bgp.MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY
	case "dsd":
		routeType = bgp.MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY
	case "t1st":
		routeType = bgp.MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED
	case "t2st":
		routeType = bgp.MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED
	default:
		// use prefix as route key
	}
	destinations := t.GetDestinations()
	results := make([]*destination, 0, len(destinations))
	switch t.Family {
	case bgp.RF_MUP_IPv4, bgp.RF_MUP_IPv6:
		for _, dst := range destinations {
			if nlri, ok := dst.nlri.(*bgp.MUPNLRI); !ok {
				return nil, fmt.Errorf("invalid mup nlri type detected: %T", dst.nlri)
			} else if nlri.RouteType == routeType {
				results = append(results, dst)
			} else if nlri.String() == p {
				results = append(results, dst)
			}
		}
	default:
		results = append(results, destinations...)
	}
	return results, nil
}

func (t *Table) setDestination(dst *destination) {
	if collision := t.destinations.InsertUpdate(dst); collision {
		// Get the first prefix in this collision bucket
		shard := t.destinations.getShard(dst.GetNlri())
		shard.mu.RLock()
		key := tableKey(dst.GetNlri())
		firstPrefix := ""
		if dests, ok := shard.mp[key]; ok && len(dests) > 0 {
			firstPrefix = dests[0].GetNlri().String()
		}
		shard.mu.RUnlock()

		t.logger.Warn("insert collision detected",
			slog.String("Topic", "Table"),
			slog.String("Key", t.Family.String()),
			slog.String("1stPrefix", firstPrefix),
			slog.String("Prefix", dst.GetNlri().String()),
		)
	}

	if nlri, ok := dst.nlri.(*bgp.EVPNNLRI); ok {
		if macadv, ok := nlri.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute); ok {
			for _, path := range dst.knownPathList {
				for _, ec := range path.GetRouteTargets() {
					t.macIndex.Insert(ec, macadv.MacAddress, dst)
				}
			}
		}
	}
}

func (t *Table) Bests(id string, as uint32) []*Path {
	paths := make([]*Path, 0)

	for _, shard := range t.destinations.shards {
		shard.mu.RLock()
		for _, dests := range shard.mp {
			for _, dest := range dests {
				path := dest.GetBestPath(id, as)
				if path != nil {
					paths = append(paths, path)
				}
			}
		}
		shard.mu.RUnlock()
	}
	return paths
}

func (t *Table) MultiBests(id string) [][]*Path {
	paths := make([][]*Path, 0)

	for _, shard := range t.destinations.shards {
		shard.mu.RLock()
		for _, dests := range shard.mp {
			for _, dest := range dests {
				path := dest.GetMultiBestPath(id)
				if path != nil {
					paths = append(paths, path)
				}
			}
		}
		shard.mu.RUnlock()
	}
	return paths
}

func (t *Table) GetKnownPathList(id string, as uint32) []*Path {
	paths := make([]*Path, 0)

	for _, shard := range t.destinations.shards {
		shard.mu.RLock()
		for _, dests := range shard.mp {
			for _, dest := range dests {
				paths = append(paths, dest.GetKnownPathList(id, as)...)
			}
		}
		shard.mu.RUnlock()
	}
	return paths
}

func (t *Table) GetKnownPathListWithMac(id string, as uint32, rt bgp.ExtendedCommunityInterface, mac net.HardwareAddr, onlyBest bool) []*Path {
	var paths []*Path
	dests := t.macIndex.Get(rt, mac)

	// For each destination, lock its shard before accessing
	for _, dst := range dests {
		shard := t.destinations.getShard(dst.nlri)
		shard.mu.RLock()
		if onlyBest {
			path := dst.GetBestPath(id, as)
			if path != nil {
				paths = append(paths, path)
			}
		} else {
			paths = append(paths, dst.GetKnownPathList(id, as)...)
		}
		shard.mu.RUnlock()
	}
	return paths
}

// mustIPAddrPrefix constructs an IPAddrPrefix from a netip.Prefix that is
// guaranteed to be valid by the caller. It panics if prefix is not valid,
// which indicates a programming error in the caller.
func mustIPAddrPrefix(prefix netip.Prefix) *bgp.IPAddrPrefix {
	nlri, err := bgp.NewIPAddrPrefix(prefix)
	if err != nil {
		panic("mustIPAddrPrefix called with invalid prefix: " + err.Error())
	}
	return nlri
}

// ContainsCIDR checks if one IPNet is a subnet of another.
func containsCIDR(n1, n2 *net.IPNet) bool {
	ones1, _ := n1.Mask.Size()
	ones2, _ := n2.Mask.Size()
	return ones1 <= ones2 && n1.Contains(n2.IP)
}

func (t *Table) Select(option ...TableSelectOption) (*Table, error) {
	id := GLOBAL_RIB_NAME
	var vrf *Vrf
	adj := false
	prefixes := make([]*apiutil.LookupPrefix, 0, len(option))
	best := false
	mp := false
	as := uint32(0)
	for _, o := range option {
		if o.ID != "" {
			id = o.ID
		}
		if o.VRF != nil {
			vrf = o.VRF
		}
		adj = o.adj
		prefixes = append(prefixes, o.LookupPrefixes...)
		best = o.Best
		mp = o.MultiPath
		as = o.AS
	}
	dOption := DestinationSelectOption{ID: id, AS: as, VRF: vrf, adj: adj, Best: best, MultiPath: mp}
	r := NewTable(nil, t.Family)

	if len(prefixes) != 0 {
		switch t.Family {
		case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
			for _, p := range prefixes {
				key := p.Prefix
				switch p.LookupOption {
				case apiutil.LOOKUP_LONGER:
					ds, err := t.GetLongerPrefixDestinations(key)
					if err != nil {
						return nil, err
					}
					for _, dst := range ds {
						if d := dst.Select(dOption); d != nil {
							r.setDestination(d)
						}
					}
				case apiutil.LOOKUP_SHORTER:
					prefix, err := netip.ParsePrefix(key)
					if err != nil {
						return nil, err
					}
					for i := prefix.Bits(); i >= 0; i-- {
						nlri := mustIPAddrPrefix(netip.PrefixFrom(prefix.Addr(), i))
						if d := t.SelectDestination(nlri, dOption); d != nil {
							r.setDestination(d)
						}
					}
				default:
					if addr, err := netip.ParseAddr(key); err == nil {
						masklen := 32
						if t.Family == bgp.RF_IPv6_UC {
							masklen = 128
						}
						for i := masklen; i >= 0; i-- {
							nlri := mustIPAddrPrefix(netip.PrefixFrom(addr, i))
							if d := t.SelectDestination(nlri, dOption); d != nil {
								r.setDestination(d)
								break
							}
						}
					} else {
						prefix, err := netip.ParsePrefix(key)
						if err != nil {
							return nil, err
						}
						nlri := mustIPAddrPrefix(prefix)
						if d := t.SelectDestination(nlri, dOption); d != nil {
							r.setDestination(d)
						}
					}
				}
			}
		case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
			f := func(prefixStr string) error {
				rd, p, err := bgp.ParseVPNPrefix(prefixStr)
				if err != nil {
					return err
				}

				nlri, _ := bgp.NewLabeledVPNIPAddrPrefix(p, *bgp.NewMPLSLabelStack(), rd)
				if d := t.SelectDestination(nlri, dOption); d != nil {
					r.setDestination(d)
				}
				return nil
			}

			for _, p := range prefixes {
				switch p.LookupOption {
				case apiutil.LOOKUP_LONGER:
					_, prefix, err := net.ParseCIDR(p.Prefix)
					if err != nil {
						return nil, err
					}

					if p.RD == "" {
						for _, dst := range t.GetDestinations() {
							tablePrefix := nlriToIPNet(dst.nlri)

							if containsCIDR(prefix, tablePrefix) {
								r.setDestination(dst)
							}
						}

						return r, nil
					}

					ds, err := t.GetLongerPrefixDestinations(p.RD + ":" + p.Prefix)
					if err != nil {
						return nil, err
					}

					for _, dst := range ds {
						if d := dst.Select(dOption); d != nil {
							r.setDestination(d)
						}
					}
				case apiutil.LOOKUP_SHORTER:
					addr, prefix, err := net.ParseCIDR(p.Prefix)
					if err != nil {
						return nil, err
					}

					if p.RD == "" {
						for _, dst := range t.GetDestinations() {
							tablePrefix := nlriToIPNet(dst.nlri)

							if containsCIDR(tablePrefix, prefix) {
								r.setDestination(dst)
							}
						}

						return r, nil
					}

					rd, err := bgp.ParseRouteDistinguisher(p.RD)
					if err != nil {
						return nil, err
					}

					ones, _ := prefix.Mask.Size()
					for i := ones; i >= 0; i-- {
						_, prefix, _ := net.ParseCIDR(addr.String() + "/" + strconv.Itoa(i))

						err := f(rd.String() + ":" + prefix.String())
						if err != nil {
							return nil, err
						}
					}
				default:
					if p.RD == "" {
						for _, dst := range t.GetDestinations() {
							net := nlriToIPNet(dst.nlri)
							if net.String() == p.Prefix {
								r.setDestination(dst)
							}
						}

						return r, nil
					}

					err := f(p.RD + ":" + p.Prefix)
					if err != nil {
						return nil, err
					}
				}
			}
		case bgp.RF_EVPN:
			for _, p := range prefixes {
				// Uses LookupPrefix.Prefix as EVPN Route Type string
				ds, err := t.GetEvpnDestinationsWithRouteType(p.Prefix)
				if err != nil {
					return nil, err
				}
				for _, dst := range ds {
					if d := dst.Select(dOption); d != nil {
						r.setDestination(d)
					}
				}
			}
		case bgp.RF_MUP_IPv4, bgp.RF_MUP_IPv6:
			for _, p := range prefixes {
				ds, err := t.GetMUPDestinationsWithRouteType(p.Prefix)
				if err != nil {
					return nil, err
				}
				for _, dst := range ds {
					if d := dst.Select(dOption); d != nil {
						r.setDestination(d)
					}
				}
			}
		default:
			return nil, fmt.Errorf("route filtering is not supported for this family")
		}
	} else {
		// Iterate with shard-level locking to ensure destination methods
		// are called while holding the appropriate lock
		for _, shard := range t.destinations.shards {
			shard.mu.RLock()
			for _, dests := range shard.mp {
				for _, dest := range dests {
					if d := dest.Select(dOption); d != nil {
						// setDestination expects to receive destinations that can be
						// safely stored (snapshots or newly created). Since Select()
						// returns a new destination, this is safe.
						r.setDestination(d)
					}
				}
			}
			shard.mu.RUnlock()
		}
	}
	return r, nil
}

type TableInfo struct {
	NumDestination int
	NumPath        int
	NumAccepted    int
	NumCollision   int
}

type TableInfoOptions struct {
	ID  string
	AS  uint32
	VRF *Vrf
}

func (t *Table) Info(option ...TableInfoOptions) *TableInfo {
	var numD, numP, numC int

	id := GLOBAL_RIB_NAME
	var vrf *Vrf
	as := uint32(0)

	for _, o := range option {
		if o.ID != "" {
			id = o.ID
		}
		if o.VRF != nil {
			vrf = o.VRF
		}
		as = o.AS
	}

	for _, shard := range t.destinations.shards {
		shard.mu.RLock()
		for _, dests := range shard.mp {
			if len(dests) > 1 {
				numC += len(dests) - 1
			}
			for _, d := range dests {
				paths := d.GetKnownPathList(id, as)
				n := len(paths)

				if vrf != nil {
					ps := make([]*Path, 0, len(paths))
					for _, p := range paths {
						if CanImportToVrf(vrf, p) {
							ps = append(ps, p.ToLocal())
						}
					}
					n = len(ps)
				}
				if n != 0 {
					numD++
					numP += n
				}
			}
		}
		shard.mu.RUnlock()
	}
	return &TableInfo{
		NumDestination: numD,
		NumPath:        numP,
		NumCollision:   numC,
	}
}

// DefaultRT is the uint64 encoding of the default (wildcard) Route Target used in RTC.
// It indicates interest in all routes, regardless of their Route Targets.
// In RouteTargetMembershipNLRI, this value is represented as a nil RouteTarget.
const DefaultRT uint64 = 0

var (
	ErrInvalidRouteTarget error = errors.New("ExtendedCommunity is not RouteTarget")
	ErrNilCommunity       error = errors.New("RouteTarget could not be nil")
)

func extCommRouteTargetKey(routeTarget bgp.ExtendedCommunityInterface) (uint64, error) {
	if routeTarget == nil {
		return 0, ErrNilCommunity
	}
	switch rt := routeTarget.(type) {
	case *bgp.TwoOctetAsSpecificExtended, *bgp.IPv4AddressSpecificExtended, *bgp.FourOctetAsSpecificExtended:
		bytes, err := rt.Serialize()
		if err != nil {
			return 0, err
		}
		return binary.BigEndian.Uint64(bytes[:]), nil
	default:
		return 0, ErrInvalidRouteTarget
	}
}

func nlriRouteTargetKey(nlri *bgp.RouteTargetMembershipNLRI) (uint64, error) {
	if nlri.RouteTarget == nil {
		return DefaultRT, nil
	}
	return extCommRouteTargetKey(nlri.RouteTarget)
}

type routeTargetMap map[uint64]bgp.ExtendedCommunityInterface

func (rtm routeTargetMap) ToSlice() []bgp.ExtendedCommunityInterface {
	s := make([]bgp.ExtendedCommunityInterface, 0, len(rtm))
	for _, rt := range rtm {
		s = append(s, rt)
	}
	return s
}

func (rtm routeTargetMap) Clone() routeTargetMap {
	rts := make(routeTargetMap, len(rtm))
	for key, rt := range rtm {
		rts[key] = rt
	}
	return rts
}

func newRouteTargetMap(s []bgp.ExtendedCommunityInterface) (routeTargetMap, error) {
	m := make(routeTargetMap, len(s))
	for _, rt := range s {
		key, err := extCommRouteTargetKey(rt)
		if err != nil {
			return nil, err
		}
		m[key] = rt
	}
	return m, nil
}
