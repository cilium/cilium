package table

import (
	"sync"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// rtmKey uniquely identifies an RT membership entry within an rtPrefix bucket.
// With ADD-PATH, the same (AS, RT) NLRI can appear with different path IDs;
// both fields are required so a withdraw of one path-ID or different AS does not cancel others.
type rtmKey struct {
	as     uint32
	pathID uint32
}

// rtPrefix is the key of an RT membership: the length of the RTC NLRI and the
// Route Target part of its prefix. The origin AS is not part of the key, it
// is kept in rtmKey. bits holds the first len-32 bits of the Route Target and
// zero in the rest. The length keeps NLRIs that differ only in length apart:
// the default RT (/0), an NLRI without a Route Target (/32), an all-zero Route
// Target (/96) and a short prefix such as /40 all have zero bits.
type rtPrefix struct {
	len  uint8
	bits uint64
}

// rtMask returns the mask of the Route Target part of an RTC NLRI of length
// l. An NLRI of length 32 or less has no Route Target part, so its mask is
// zero and it matches every Route Target.
func rtMask(l uint8) uint64 {
	if l <= 32 {
		return 0
	}
	return ^uint64(0) << (bgp.RouteTargetMembershipPrefixLen - int(l))
}

// rtLen returns the length of the Route Target part of an RTC NLRI of
// length l. The default RT (/0) and an NLRI with the origin AS only (/32)
// both have none, so they cover the same Route Targets: all of them.
func rtLen(l uint8) uint8 {
	if l <= 32 {
		return 0
	}
	return l - 32
}

// routeTargetTypes are the Type Fields of a Route Target, as the first 16
// bits of a Route Target key. RFC 4360 Section 4: "The value of the
// high-order octet of the Type field for the Route Target Community can be
// 0x00, 0x01, or 0x02. The value of the low-order octet of the Type field
// for this community is 0x02."
var routeTargetTypes = [...]uint64{
	uint64(bgp.EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC)<<56 | uint64(bgp.EC_SUBTYPE_ROUTE_TARGET)<<48,
	uint64(bgp.EC_TYPE_TRANSITIVE_IP4_SPECIFIC)<<56 | uint64(bgp.EC_SUBTYPE_ROUTE_TARGET)<<48,
	uint64(bgp.EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC)<<56 | uint64(bgp.EC_SUBTYPE_ROUTE_TARGET)<<48,
}

// rtPrefixOf returns the rtPrefix of nlri. It returns false when the NLRI
// has an invalid length, or when it cannot contain any Route Target.
func rtPrefixOf(nlri *bgp.RouteTargetMembershipNLRI) (rtPrefix, bool) {
	// RFC 4684 Section 4: the prefix is 0 to 96 bits, and other than the
	// zero-length default route target it is at least 32 bits.
	if nlri.Length != 0 && nlri.Length < 32 || nlri.Length > bgp.RouteTargetMembershipPrefixLen {
		return rtPrefix{}, false
	}
	key, err := nlri.RouteTargetKey()
	if err != nil {
		return rtPrefix{}, false
	}
	// A received NLRI has its trailing bits cleared already, but one built
	// locally keeps the whole Route Target whatever its length is.
	mask := rtMask(nlri.Length)
	bits := key & mask
	// Only a Route Target is looked up, so a prefix that contains none is
	// never matched. Keep such an NLRI out. A prefix that covers only part
	// of the Type Field, or none of it, is kept when that part fits a Route
	// Target type.
	typeMask := mask & (0xffff << 48)
	for _, t := range routeTargetTypes {
		if bits&typeMask == t&typeMask {
			return rtPrefix{len: nlri.Length, bits: bits}, true
		}
	}
	return rtPrefix{}, false
}

// rtmSet tracks which (AS, pathID) pairs are present per rtPrefix.
// Set semantics make ADD-PATH or different AS withdrawals safe: removing one path-ID does not
// affect others sharing the same prefix, and spurious removes are no-ops.
// Thread-safe: add/sub are called under a shard write-lock, contains is called from
// interestedIn without any lock, so an internal RWMutex is required.
type rtmSet struct {
	mu sync.RWMutex
	m  map[rtPrefix]map[rtmKey]struct{}
	// count[l] is the number of prefixes of length l in m. A length is
	// deleted when its count drops to zero, so that contains looks up only
	// the lengths in use. There are only a few of them in practice.
	count map[uint8]int
}

func newRtmSet() *rtmSet {
	return &rtmSet{
		m:     make(map[rtPrefix]map[rtmKey]struct{}),
		count: make(map[uint8]int),
	}
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
	prefix, ok := rtPrefixOf(nlri)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, ok := s.m[prefix]
	if !ok {
		keys = make(map[rtmKey]struct{})
		s.m[prefix] = keys
		s.count[prefix.len]++
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
	prefix, ok := rtPrefixOf(nlri)
	if !ok {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	keys, ok := s.m[prefix]
	if !ok {
		return
	}
	delete(keys, rtmKey{as: nlri.AS, pathID: path.remoteID})
	if len(keys) == 0 {
		delete(s.m, prefix)
		s.count[prefix.len]--
		if s.count[prefix.len] == 0 {
			delete(s.count, prefix.len)
		}
	}
}

// has reports whether prefix itself is present.
func (s *rtmSet) has(prefix rtPrefix) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m[prefix]) > 0
}

// contains reports whether a present prefix contains the Route Target whose
// key is rtKey. A prefix of length 32 or less contains every Route Target.
func (s *rtmSet) contains(rtKey uint64) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Any containing prefix is enough, so the order does not matter.
	for l := range s.count {
		if len(s.m[rtPrefix{len: l, bits: rtKey & rtMask(l)}]) > 0 {
			return true
		}
	}
	return false
}

// containsAll reports whether a present prefix contains every Route Target:
// the default RT (/0) or an NLRI without a Route Target (/32).
func (s *rtmSet) containsAll() bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m[rtPrefix{len: 0}]) > 0 || len(s.m[rtPrefix{len: 32}]) > 0
}

// covers reports whether a present prefix contains every Route Target that
// prefix contains. That is a prefix whose Route Target part is not longer
// than the one of prefix and matches it.
func (s *rtmSet) covers(prefix rtPrefix) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for l := range s.count {
		if rtLen(l) > rtLen(prefix.len) {
			continue
		}
		if len(s.m[rtPrefix{len: l, bits: prefix.bits & rtMask(l)}]) > 0 {
			return true
		}
	}
	return false
}

func (s *rtmSet) reset() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = make(map[rtPrefix]map[rtmKey]struct{})
	s.count = make(map[uint8]int)
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
	rts map[uint64]*vpnRTEntry // rtHash -> entry
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
	for _, ext := range path.GetRouteTargets() {
		rtHash, err := bgp.ExtCommRouteTargetKey(ext)
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
	for _, ext := range path.GetRouteTargets() {
		rtHash, err := bgp.ExtCommRouteTargetKey(ext)
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
	rtHash, err := bgp.ExtCommRouteTargetKey(rt)
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

// HasRouteTarget reports whether the peer advertised an RT membership that
// contains routeTarget. A membership is a prefix, so it can contain more than
// one Route Target, and the default RT contains every one of them.
func (handler *RouteTargetMembershipHandler) HasRouteTarget(routeTarget bgp.ExtendedCommunityInterface) bool {
	if handler == nil || handler.s == nil {
		return false
	}
	key, err := bgp.ExtCommRouteTargetKey(routeTarget)
	if err != nil {
		return false
	}
	return handler.s.contains(key)
}

// HasDefaultRouteTarget reports whether the peer advertised an RT membership
// that contains every Route Target. That is the default RT (/0), or an NLRI
// that has the origin AS only (/32).
func (handler *RouteTargetMembershipHandler) HasDefaultRouteTarget() bool {
	if handler == nil || handler.s == nil {
		return false
	}
	return handler.s.containsAll()
}

// Covers reports whether the peer advertised RT memberships that contain
// every Route Target nlri contains, so that advertising or withdrawing nlri
// alone changes nothing for the peer. It returns false for an NLRI that
// rtmSet does not keep.
func (handler *RouteTargetMembershipHandler) Covers(nlri *bgp.RouteTargetMembershipNLRI) bool {
	if handler == nil || handler.s == nil {
		return false
	}
	prefix, ok := rtPrefixOf(nlri)
	if !ok {
		return false
	}
	return handler.s.covers(prefix)
}

// RouteTargetMembershipContains reports whether nlri contains one of the
// Route Targets of path.
func RouteTargetMembershipContains(nlri *bgp.RouteTargetMembershipNLRI, path *Path) bool {
	prefix, ok := rtPrefixOf(nlri)
	if !ok {
		return false
	}
	mask := rtMask(prefix.len)
	for _, rt := range path.GetRouteTargets() {
		key, err := bgp.ExtCommRouteTargetKey(rt)
		if err != nil {
			continue
		}
		if key&mask == prefix.bits {
			return true
		}
	}
	return false
}

// Reset clears all tracked memberships (e.g. when Adj-RIB-In for RTC is dropped).
func (handler *RouteTargetMembershipHandler) Reset() {
	if handler == nil || handler.s == nil {
		return
	}
	handler.s.reset()
}
