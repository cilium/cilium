package table

import (
	"sync"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// rtmKey uniquely identifies an RT membership entry within an RT hash bucket.
// With ADD-PATH, the same (AS, RT) NLRI can appear with different path IDs;
// both fields are required so a withdraw of one path-ID or different AS does not cancel others.
type rtmKey struct {
	as     uint32
	pathID uint32
}

// rtmSet tracks which (AS, pathID) pairs are present per RT hash.
// Set semantics make ADD-PATH or different AS withdrawals safe: removing one path-ID does not
// affect others sharing the same RT, and spurious removes are no-ops.
// Thread-safe: add/sub are called under a shard write-lock, has is called from
// interestedIn without any lock, so an internal RWMutex is required.
type rtmSet struct {
	mu sync.RWMutex
	m  map[uint64]map[rtmKey]struct{}
}

func newRtmSet() *rtmSet {
	return &rtmSet{m: make(map[uint64]map[rtmKey]struct{})}
}

func (s *rtmSet) add(path *Path) {
	if s == nil {
		return
	}
	if path.GetFamily() != bgp.RF_RTC_UC {
		return
	}
	nlri, ok := path.GetNlri().(*bgp.RouteTargetMembershipNLRI)
	if !ok {
		return
	}
	rtHash, err := nlriRouteTargetKey(nlri)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, ok := s.m[rtHash]
	if !ok {
		keys = make(map[rtmKey]struct{})
		s.m[rtHash] = keys
	}
	keys[rtmKey{as: nlri.AS, pathID: path.remoteID}] = struct{}{}
}

func (s *rtmSet) sub(path *Path) {
	if s == nil {
		return
	}
	if path.GetFamily() != bgp.RF_RTC_UC {
		return
	}
	nlri, ok := path.GetNlri().(*bgp.RouteTargetMembershipNLRI)
	if !ok {
		return
	}
	rtHash, err := nlriRouteTargetKey(nlri)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, ok := s.m[rtHash]
	if !ok {
		return
	}
	delete(keys, rtmKey{as: nlri.AS, pathID: path.remoteID})
	if len(keys) == 0 {
		delete(s.m, rtHash)
	}
}

func (s *rtmSet) has(rtHash uint64) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m[rtHash]) > 0
}

func (s *rtmSet) reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = make(map[uint64]map[rtmKey]struct{})
}

// vpnPathKey identifies a VPN path without relying on *Path pointer identity.
// info points to the root originInfo shared by a path and all its clones, so
// Register/Unregister match even when the path was cloned in the pipeline.
type vpnPathKey struct {
	info   *originInfo
	pathID uint32
}

func makeVPNPathKey(path *Path) vpnPathKey {
	return vpnPathKey{info: path.OriginInfo(), pathID: path.remoteID}
}

// vpnRTEntry holds the set of paths indexed under a single RT hash.
type vpnRTEntry struct {
	paths map[vpnPathKey]*Path
}

func newVPNRTEntry() *vpnRTEntry {
	return &vpnRTEntry{paths: make(map[vpnPathKey]*Path)}
}

// VPNPathIndex is a standalone thread-safe index of VPN (and similar) paths by Route Target.
// It lives inside each VPN-family Table and is maintained as paths enter or leave the table,
// enabling O(1) RT-based candidate lookup during RTC processing instead of a linear scan.
//
// Thread-safe: all operations are protected by an internal RWMutex.
type VPNPathIndex struct {
	mu  sync.RWMutex
	rts map[uint64]*vpnRTEntry // rtHash → entry
}

func NewVPNPathIndex() *VPNPathIndex {
	return &VPNPathIndex{rts: make(map[uint64]*vpnRTEntry)}
}

// RegisterPath indexes path under each of its RT extended communities.
// No-op for nil, EOR, or withdraw paths and for paths with no RT ext comms.
func (idx *VPNPathIndex) RegisterPath(path *Path) {
	if idx == nil || path == nil || path.IsEOR() || path.IsWithdraw {
		return
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	for _, ext := range path.GetExtCommunities() {
		rtHash, err := extCommRouteTargetKey(ext)
		if err != nil {
			continue
		}
		entry, ok := idx.rts[rtHash]
		if !ok {
			entry = newVPNRTEntry()
			idx.rts[rtHash] = entry
		}
		entry.paths[makeVPNPathKey(path)] = path
	}
}

// UnregisterPath removes path from the index. Spurious removes are no-ops.
func (idx *VPNPathIndex) UnregisterPath(path *Path) {
	if idx == nil || path == nil || path.IsEOR() {
		return
	}
	idx.mu.Lock()
	defer idx.mu.Unlock()
	for _, ext := range path.GetExtCommunities() {
		rtHash, err := extCommRouteTargetKey(ext)
		if err != nil {
			continue
		}
		entry, ok := idx.rts[rtHash]
		if !ok {
			continue
		}
		delete(entry.paths, makeVPNPathKey(path))
		if len(entry.paths) == 0 {
			delete(idx.rts, rtHash)
		}
	}
}

// GetPathsByRT returns all indexed paths whose extended communities include rt.
// If rt is nil (wildcard), returns nil.
func (idx *VPNPathIndex) GetPathsByRT(rt bgp.ExtendedCommunityInterface) []*Path {
	if idx == nil || rt == nil {
		return nil
	}
	rtHash, err := extCommRouteTargetKey(rt)
	if err != nil {
		return nil
	}
	idx.mu.RLock()
	defer idx.mu.RUnlock()
	entry, ok := idx.rts[rtHash]
	if !ok {
		return nil
	}
	paths := make([]*Path, 0, len(entry.paths))
	for _, p := range entry.paths {
		paths = append(paths, p)
	}
	return paths
}

// RouteTargetMembershipHandler tracks Route Target membership NLRI keys learned from a
// peer that count for RTC constrained route distribution, after import policy.
type RouteTargetMembershipHandler struct {
	s *rtmSet
}

func NewRouteTargetMembershipHandler() *RouteTargetMembershipHandler {
	return &RouteTargetMembershipHandler{s: newRtmSet()}
}

// SyncAfterImport updates the set from the RTC path as seen after import policy:
// accepted advertisements add membership; withdrawals (including import rejects
// represented as withdrawals) remove it.
func (handler *RouteTargetMembershipHandler) SyncAfterImport(path *Path) {
	if handler == nil || handler.s == nil {
		return
	}
	if path == nil || path.IsEOR() || path.GetFamily() != bgp.RF_RTC_UC {
		return
	}
	if path.IsWithdraw {
		handler.s.sub(path)
	} else {
		handler.s.add(path)
	}
}

func (handler *RouteTargetMembershipHandler) HasRouteTarget(routeTarget bgp.ExtendedCommunityInterface) bool {
	if handler == nil || handler.s == nil {
		return false
	}
	key, err := extCommRouteTargetKey(routeTarget)
	if err != nil {
		return false
	}
	return handler.s.has(key)
}

func (handler *RouteTargetMembershipHandler) HasDefaultRouteTarget() bool {
	if handler == nil || handler.s == nil {
		return false
	}
	return handler.s.has(DefaultRT)
}

// Reset clears all tracked memberships (e.g. when Adj-RIB-In for RTC is dropped).
func (handler *RouteTargetMembershipHandler) Reset() {
	if handler == nil || handler.s == nil {
		return
	}
	handler.s.reset()
}
