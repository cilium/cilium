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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"slices"
	"sort"
	"sync/atomic"
	"time"

	"github.com/dgryski/go-farm"

	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

const (
	DEFAULT_LOCAL_PREF = 100
)

var ErrNoMedPathAttr error = errors.New("no med path attr")

type Bitmap struct {
	bitmap []uint64
}

func (b *Bitmap) Flag(i uint) {
	b.bitmap[i/64] |= 1 << (i % 64)
}

func (b *Bitmap) Unflag(i uint) {
	b.bitmap[i/64] &^= 1 << (i % 64)
}

func (b *Bitmap) GetFlag(i uint) bool {
	return b.bitmap[i/64]&(1<<(i%64)) > 0
}

func (b *Bitmap) FindandSetZeroBit() (uint, error) {
	for i := range len(b.bitmap) {
		if b.bitmap[i] == math.MaxUint64 {
			continue
		}
		// replace this with TrailingZero64() when gobgp drops go 1.8 support.
		for j := range 64 {
			v := ^b.bitmap[i]
			if v&(1<<uint64(j)) > 0 {
				r := i*64 + j
				b.Flag(uint(r))
				return uint(r), nil
			}
		}
	}
	return 0, fmt.Errorf("no space")
}

func (b *Bitmap) Expand() {
	b.bitmap = append(b.bitmap, uint64(0))
}

func NewBitmap(size int) *Bitmap {
	b := &Bitmap{}
	if size != 0 {
		b.bitmap = make([]uint64, (size+64-1)/64)
	}
	return b
}

type originInfo struct {
	nlri       bgp.NLRI
	nlriString string
	source     *PeerInfo
	timestamp  int64
	// stale is the only field written after the path has been handed to
	// another goroutine. AdjRib.StaleAll writes it through Path.root() while
	// the watcher goroutines read it with IsStale(), and no lock covers both
	// sides, so it has to be atomic.
	stale              atomic.Bool
	noImplicitWithdraw bool
	isFromExternal     bool
	eor                bool
}

type RpkiValidationReasonType string

const (
	RPKI_VALIDATION_REASON_TYPE_NONE   RpkiValidationReasonType = "none"
	RPKI_VALIDATION_REASON_TYPE_AS     RpkiValidationReasonType = "as"
	RPKI_VALIDATION_REASON_TYPE_LENGTH RpkiValidationReasonType = "length"
)

var RpkiValidationReasonTypeToIntMap = map[RpkiValidationReasonType]int{
	RPKI_VALIDATION_REASON_TYPE_NONE:   0,
	RPKI_VALIDATION_REASON_TYPE_AS:     1,
	RPKI_VALIDATION_REASON_TYPE_LENGTH: 2,
}

func (v RpkiValidationReasonType) ToInt() int {
	i, ok := RpkiValidationReasonTypeToIntMap[v]
	if !ok {
		return -1
	}
	return i
}

var IntToRpkiValidationReasonTypeMap = map[int]RpkiValidationReasonType{
	0: RPKI_VALIDATION_REASON_TYPE_NONE,
	1: RPKI_VALIDATION_REASON_TYPE_AS,
	2: RPKI_VALIDATION_REASON_TYPE_LENGTH,
}

type Validation struct {
	Status          oc.RpkiValidationResultType
	Reason          RpkiValidationReasonType
	Matched         []*ROA
	UnmatchedAs     []*ROA
	UnmatchedLength []*ROA
}

type Path struct {
	info      *originInfo
	parent    *Path
	pathAttrs []bgp.PathAttributeInterface
	dels      []bgp.BGPAttrType
	attrsHash atomic.Uint64
	// nh is the next hop of the path. It is never changed after it is
	// set, so paths can share it: the paths made from one UPDATE do, and
	// Clone copies the pointer. It is nil when the path has no next hop
	// information, such as a received withdrawal.
	nh       *Nexthops
	localID  uint32
	remoteID uint32
	family   bgp.Family
	rejected bool
	// doesn't exist in the adj
	dropped bool

	// For BGP Nexthop Tracking, this field shows if nexthop is invalidated by IGP.
	IsNexthopInvalid bool
	IsWithdraw       bool
}

type FilteredType uint8

const (
	NotFiltered FilteredType = 1 << iota
	PolicyFiltered
	SendMaxFiltered
)

type PathDestLocalKey struct {
	Family bgp.Family
	Prefix string
}
type PathLocalKey struct {
	PathDestLocalKey
	Id uint32
}

func NewPathDestLocalKey(f bgp.Family, destPrefix string) *PathDestLocalKey {
	return &PathDestLocalKey{
		Family: f,
		Prefix: destPrefix,
	}
}

var localSource = &PeerInfo{}

func NewPath(family bgp.Family, source *PeerInfo, pathnlri bgp.PathNLRI, isWithdraw bool, pattrs []bgp.PathAttributeInterface, timestamp time.Time, noImplicitWithdraw bool) *Path {
	if source == nil {
		source = localSource
	}
	if !isWithdraw && pattrs == nil {
		return nil
	}
	nlriString := ""
	if pathnlri.NLRI != nil {
		nlriString = pathnlri.NLRI.String()
	}
	pattrs, nh := extractNexthops(pattrs)
	return &Path{
		info: &originInfo{
			nlri:               pathnlri.NLRI,
			nlriString:         nlriString,
			source:             source,
			timestamp:          timestamp.Unix(),
			noImplicitWithdraw: noImplicitWithdraw,
		},
		family:     family,
		IsWithdraw: isWithdraw,
		pathAttrs:  pattrs,
		nh:         nh,
		remoteID:   pathnlri.ID,
	}
}

// extractNexthops takes NEXT_HOP and MP_REACH_NLRI out of attrs and
// returns the rest and the next hops they carry. A path keeps its next hop
// outside of the path attributes. When both are in attrs, MP_REACH_NLRI is
// used. attrs is not changed, and it is returned as it is when it has
// neither attribute.
func extractNexthops(attrs []bgp.PathAttributeInterface) ([]bgp.PathAttributeInterface, *Nexthops) {
	found := false
	for _, a := range attrs {
		if t := a.GetType(); t == bgp.BGP_ATTR_TYPE_NEXT_HOP || t == bgp.BGP_ATTR_TYPE_MP_REACH_NLRI {
			found = true
			break
		}
	}
	if !found {
		return attrs, nil
	}
	var nh, mp *Nexthops
	rest := make([]bgp.PathAttributeInterface, 0, len(attrs)-1)
	for _, a := range attrs {
		switch a := a.(type) {
		case *bgp.PathAttributeNextHop:
			nh = &Nexthops{global: a.Value}
		case *bgp.PathAttributeMpReachNLRI:
			mp = newMpReachNexthops(a.Nexthop, a.LinkLocalNexthop)
		default:
			rest = append(rest, a)
		}
	}
	if mp != nil {
		return rest, mp
	}
	return rest, nh
}

func NewEOR(family bgp.Family) *Path {
	return &Path{
		family: family,
		info: &originInfo{
			eor: true,
		},
	}
}

func (path *Path) IsEOR() bool {
	if path.info != nil && path.info.eor {
		return true
	}
	return false
}

func cloneAsPath(asAttr *bgp.PathAttributeAsPath) *bgp.PathAttributeAsPath {
	newASparams := make([]bgp.AsPathParamInterface, len(asAttr.Value))
	for i, param := range asAttr.Value {
		asList := param.GetAS()
		as := make([]uint32, len(asList))
		copy(as, asList)
		newASparams[i] = bgp.NewAs4PathParam(param.GetType(), as)
	}
	return bgp.NewPathAttributeAsPath(newASparams)
}

// learnedOnSameLink reports whether the path was learned over the same
// interface as the session described by info.
//
// gobgp knows the interface of a session only when the peer address is a
// link-local address, which carries a zone. Both sessions must have one and
// they must be equal.
func (path *Path) learnedOnSameLink(info *PeerInfo) bool {
	zone := path.GetSource().Address.Zone()
	return zone != "" && zone == info.Address.Zone()
}

// updateLinkLocalNexthop drops the link-local part of the next hop when the
// peer we advertise to is not on the link the next hop belongs to.
//
// RFC 2545 3. Constructing the Next Hop field
//
//	The link-local address shall be included in the Next Hop field if and
//	only if the BGP speaker shares a common subnet with the entity
//	identified by the global IPv6 address carried in the Network Address
//	of Next Hop field and the peer the route is being advertised to.
//
//	In all other cases a BGP speaker shall advertise to its peer in the
//	Network Address field only the global IPv6 address of the next hop
//	(the value of the Length of Network Address of Next Hop field shall
//	be set to 16).
//
// gobgp can only tell that two sessions share a link when both use a
// link-local peer address on the same interface. Every other case takes the
// second rule and sends the global address alone.
//
// A peer with no global address on the link puts an unspecified or a
// link-local address in the global part of the next hop, so there is no global
// address to fall back to. Such a next hop is only usable on the link it came
// from, so we make ourselves the next hop instead. BIRD (bgp_use_next_hop) and
// FRR (bpacket_reformat_for_peer) do the same, and both treat an unspecified
// and a link-local global address alike.
func updateLinkLocalNexthop(info *PeerInfo, path *Path) {
	nexthops := path.nexthops()
	globalNexthop, linkLocalNexthop := nexthops.global, nexthops.linkLocal
	// An IPv4 next hop has no link-local form in an MP_REACH_NLRI
	// attribute, so leave it alone. 169.254.0.0/16 is not handled here.
	onLink := globalNexthop.Is6() && !globalNexthop.Is4In6() &&
		(globalNexthop.IsUnspecified() || globalNexthop.IsLinkLocalUnicast())
	if !onLink && !linkLocalNexthop.IsValid() {
		return
	}
	if path.learnedOnSameLink(info) {
		return
	}
	if path.IsLocal() && !globalNexthop.IsUnspecified() {
		// The next hop was set by the operator, keep it as it is. An
		// unspecified one is still replaced, because the peer cannot
		// use it and because that is what the switch below does for
		// every other family.
		return
	}
	if onLink {
		// The zone is stripped because a BGP next hop cannot carry one.
		globalNexthop = info.LocalAddress.WithZone("")
	}
	path.SetNexthop(globalNexthop)
}

// aigpSession reports whether AIGP is enabled on the session with the peer,
// which is the RFC 7311 default: every session but a non-confederation eBGP
// one. A local path has no session and keeps the attribute.
func aigpSession(info *PeerInfo) bool {
	return info.PeerType != oc.PEER_TYPE_EXTERNAL || info.Confederation
}

func UpdatePathAttrs(logger *slog.Logger, global *oc.Global, info *PeerInfo, original *Path) *Path {
	if info.RouteServerClient {
		return original
	}
	path := original.Clone(original.IsWithdraw)

	// RFC 4456 6: a route from a client is reflected to the non-client
	// peers as well as to the clients, and Section 8 sets ORIGINATOR_ID
	// and CLUSTER_LIST on every reflected route.
	src := path.GetSource()
	fromClient := src.PeerType == oc.PEER_TYPE_INTERNAL && src.RouteReflectorClient
	reflected := info.PeerType == oc.PEER_TYPE_INTERNAL && (info.RouteReflectorClient || fromClient)

	for _, a := range path.GetPathAttrs() {
		if _, y := bgp.PathAttrFlags[a.GetType()]; !y {
			if a.GetFlags()&bgp.BGP_ATTR_FLAG_TRANSITIVE == 0 {
				path.delPathAttr(a.GetType())
			}
		} else {
			switch a.GetType() {
			case bgp.BGP_ATTR_TYPE_CLUSTER_LIST, bgp.BGP_ATTR_TYPE_ORIGINATOR_ID:
				if !reflected {
					path.delPathAttr(a.GetType())
				}
			case bgp.BGP_ATTR_TYPE_AIGP:
				// RFC 7311 3.3: AIGP is disabled on an eBGP session that is
				// not a confederation one, and we have no knob to enable it.
				// It is not sent on such a session, and one received on it is
				// an unrecognized non-transitive attribute, not passed along.
				if !aigpSession(info) || !aigpSession(path.GetSource()) {
					path.delPathAttr(a.GetType())
				}
			}
		}
	}

	updateLinkLocalNexthop(info, path)

	nexthop := path.GetNexthop()
	switch info.PeerType {
	case oc.PEER_TYPE_EXTERNAL:
		// NEXTHOP handling
		if !path.IsLocal() || nexthop.IsUnspecified() {
			path.setNexthopsShared(info.localAddressNexthops())
		}

		// remove-private-as handling
		path.RemovePrivateAS(info.LocalAS, info.RemovePrivateAs)

		// AS_PATH handling
		confed := global.IsConfederationMember(info.AS)
		path.PrependAsn(info.LocalAS, 1, confed)
		if !confed {
			path.removeConfedAs()
		}

		// MED Handling
		if med := path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC); med != nil && !path.IsLocal() {
			path.delPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
		}
	case oc.PEER_TYPE_INTERNAL:
		// NEXTHOP handling for iBGP
		// if the path generated locally set local address as nexthop.
		// if not, don't modify it.
		// TODO: NEXT-HOP-SELF support
		if path.IsLocal() && nexthop.IsUnspecified() {
			path.setNexthopsShared(info.localAddressNexthops())
		}

		// AS_PATH handling for iBGP
		// if the path has AS_PATH path attribute, don't modify it.
		// if not, attach *empty* AS_PATH path attribute.
		if nh := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH); nh == nil {
			path.PrependAsn(0, 0, false)
		}

		// For iBGP peers we are required to send local-pref attribute
		// for connected or local prefixes.
		// We set default local-pref 100.
		if pref := path.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF); pref == nil {
			path.setPathAttr(bgp.NewPathAttributeLocalPref(DEFAULT_LOCAL_PREF))
		}

		// RFC4456: BGP Route Reflection
		// 8. Avoiding Routing Information Loops
		if reflected {
			// This attribute will carry the BGP Identifier of the originator of the route in the local AS.
			// A BGP speaker SHOULD NOT create an ORIGINATOR_ID attribute if one already exists.
			//
			// RFC4684 3.2 Intra-AS VPN Route Distribution
			// When advertising RT membership NLRI to a route-reflector client,
			// the Originator attribute shall be set to the router-id of the
			// advertiser, and the Next-hop attribute shall be set of the local
			// address for that session.
			var attr *bgp.PathAttributeOriginatorId
			if path.GetFamily() == bgp.RF_RTC_UC && info.RouteReflectorClient {
				path.setNexthopsShared(info.localAddressNexthops())
				if path.IsLocal() {
					attr, _ = bgp.NewPathAttributeOriginatorId(global.Config.RouterId)
				} else {
					attr, _ = bgp.NewPathAttributeOriginatorId(src.LocalID)
				}
			} else if path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGINATOR_ID) == nil {
				if path.IsLocal() {
					attr, _ = bgp.NewPathAttributeOriginatorId(global.Config.RouterId)
				} else {
					attr, _ = bgp.NewPathAttributeOriginatorId(src.ID)
				}
			}

			if attr != nil {
				path.setPathAttr(attr)
			}
			// When an RR reflects a route, it MUST prepend the local CLUSTER_ID to the CLUSTER_LIST.
			// If the CLUSTER_LIST is empty, it MUST create a new one.
			clusterID := info.RouteReflectorClusterID
			if !info.RouteReflectorClient {
				// A non-client has no cluster. The route is reflected
				// from the cluster of the client it was learned from.
				clusterID = src.RouteReflectorClusterID
			}
			if !clusterID.IsValid() {
				// The config defaults set the cluster ID of a client to
				// the router ID. A PeerInfo built without them has none.
				// RFC 4456 7: "Usually, a cluster of clients will have a
				// single RR. In that case, the cluster will be identified
				// by the BGP Identifier of the RR."
				clusterID = global.Config.RouterId
			}
			list := []netip.Addr{clusterID}
			if p := path.getPathAttr(bgp.BGP_ATTR_TYPE_CLUSTER_LIST); p != nil {
				list = append(list, p.(*bgp.PathAttributeClusterList).Value...)
			}
			if pa, err := bgp.NewPathAttributeClusterList(list); err != nil {
				logger.Warn("failed to build CLUSTER_LIST",
					slog.String("Topic", "Peer"),
					slog.String("Key", info.Address.String()),
					slog.Any("Error", err))
			} else {
				path.setPathAttr(pa)
			}
		}
	default:
		logger.Warn("invalid peer type",
			slog.String("Topic", "Peer"),
			slog.String("Key", info.Address.String()),
			slog.Any("Type", info.PeerType))
	}
	return path
}

func (path *Path) GetTimestamp() time.Time {
	return time.Unix(path.OriginInfo().timestamp, 0)
}

func (path *Path) setTimestamp(t time.Time) {
	path.OriginInfo().timestamp = t.Unix()
}

func (path *Path) IsLocal() bool {
	return !path.GetSource().Address.IsValid()
}

func (path *Path) IsIBGP() bool {
	as := path.GetSource().AS
	return as == path.GetSource().LocalAS && as != 0
}

// create new PathAttributes
func (path *Path) Clone(isWithdraw bool) *Path {
	p := &Path{
		parent:           path,
		family:           path.family,
		IsWithdraw:       isWithdraw,
		IsNexthopInvalid: path.IsNexthopInvalid,
		localID:          path.localID,
		remoteID:         path.remoteID,
		nh:               path.nh,
	}
	p.attrsHash.Store(path.attrsHash.Load())
	return p
}

func (path *Path) root() *Path {
	p := path
	for p.parent != nil {
		p = p.parent
	}
	return p
}

func (path *Path) OriginInfo() *originInfo {
	return path.root().info
}

func (path *Path) NoImplicitWithdraw() bool {
	return path.OriginInfo().noImplicitWithdraw
}

func (path *Path) IsFromExternal() bool {
	return path.OriginInfo().isFromExternal
}

func (path *Path) SetIsFromExternal(y bool) {
	path.OriginInfo().isFromExternal = y
}

func (path *Path) GetFamily() bgp.Family {
	return path.family
}

func (path *Path) GetSource() *PeerInfo {
	return path.OriginInfo().source
}

func (path *Path) MarkStale(s bool) {
	path.OriginInfo().stale.Store(s)
}

func (path *Path) IsStale() bool {
	return path.OriginInfo().stale.Load()
}

func (path *Path) IsRejected() bool {
	return path.rejected
}

func (path *Path) SetRejected(y bool) {
	path.rejected = y
}

func (path *Path) IsDropped() bool {
	return path.dropped
}

func (path *Path) SetDropped(y bool) {
	path.dropped = y
}

func (path *Path) HasNoLLGR() bool {
	return slices.Contains(path.GetCommunities(), uint32(bgp.COMMUNITY_NO_LLGR))
}

func (path *Path) IsLLGRStale() bool {
	return slices.Contains(path.GetCommunities(), uint32(bgp.COMMUNITY_LLGR_STALE))
}

func (path *Path) GetSourceAs() uint32 {
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	if attr != nil {
		asPathParam := attr.(*bgp.PathAttributeAsPath).Value
		if len(asPathParam) == 0 {
			return 0
		}
		asList := asPathParam[len(asPathParam)-1].GetAS()
		if len(asList) == 0 {
			return 0
		}
		return asList[len(asList)-1]
	}
	return 0
}

func (path *Path) GetNexthop() netip.Addr {
	n := path.nexthops()
	// A peer with no global address on the link sends an unspecified
	// global address together with the link-local one. The link-local
	// address is the only next hop we can use then. The next hops are
	// kept as they are so that the received form is sent to the peers
	// that share the link.
	if n.global.IsUnspecified() && n.linkLocal.IsValid() {
		return n.linkLocal
	}
	return n.global
}

// Nexthops holds the next hops of a path. global is the NEXT_HOP value or
// the first next hop in MP_REACH_NLRI, and linkLocal is the second one in
// MP_REACH_NLRI. An invalid netip.Addr means the next hop is absent.
// linkLocal is either invalid or a link-local unicast address, see
// newMpReachNexthops.
type Nexthops struct {
	global, linkLocal netip.Addr
}

// newMpReachNexthops returns the next hops carried in MP_REACH_NLRI. The
// second next hop is dropped unless it is a link-local unicast address. It
// has no use then, and it is not sent either: NewPathAttributeMpReachNLRI
// writes the second next hop only when it is link-local. BIRD
// (bgp_decode_next_hop_ip) and FRR (bgp_mp_reach_parse) ignore it the same
// way.
func newMpReachNexthops(global, linkLocal netip.Addr) *Nexthops {
	if !linkLocal.IsLinkLocalUnicast() {
		linkLocal = netip.Addr{}
	}
	return &Nexthops{global: global, linkLocal: linkLocal}
}

// list returns the valid next hops, the global one first.
func (n Nexthops) list() []netip.Addr {
	l := make([]netip.Addr, 0, 2)
	if n.global.IsValid() {
		l = append(l, n.global)
	}
	if n.linkLocal.IsValid() {
		l = append(l, n.linkLocal)
	}
	return l
}

// nexthops returns the next hops of path as they are stored. Unlike
// GetNexthop, it does not pick the link-local next hop when the global
// one is unspecified.
func (path *Path) nexthops() Nexthops {
	if path.nh == nil {
		return Nexthops{}
	}
	return *path.nh
}

// setNexthops sets the next hops of path.
func (path *Path) setNexthops(n Nexthops) {
	path.nh = &n
}

// SetNexthop sets nexthop as the next hop of path and drops the
// link-local one. A path with no next hop information, such as a received
// withdrawal, is left as it is.
func (path *Path) SetNexthop(nexthop netip.Addr) {
	if path.nh == nil {
		return
	}
	path.nh = &Nexthops{global: nexthop}
}

// setNexthopsShared sets n as the next hops of path, without making a
// copy. n must not be changed after this. Like SetNexthop, it leaves a
// path with no next hop information as it is.
func (path *Path) setNexthopsShared(n *Nexthops) {
	if path.nh == nil {
		return
	}
	path.nh = n
}

// nexthopAttr returns the attribute that carries the next hop of path: a
// NEXT_HOP for an IPv4 unicast path with an IPv4 next hop, and an
// MP_REACH_NLRI with the NLRI of path for any other path. id is the path
// identifier of the NLRI. It returns nil when path has no next hop
// information.
func (path *Path) nexthopAttr(id uint32) bgp.PathAttributeInterface {
	if path.nh == nil {
		return nil
	}
	n := *path.nh
	if path.GetFamily() == bgp.RF_IPv4_UC && n.global.Is4() {
		a, _ := bgp.NewPathAttributeNextHop(n.global)
		return a
	}
	a, err := bgp.NewPathAttributeMpReachNLRI(path.GetFamily(), []bgp.PathNLRI{{NLRI: path.GetNlri(), ID: id}}, n.list()...)
	if err != nil {
		return nil
	}
	return a
}

// insertPathAttr inserts a into attrs before the first attribute with a
// larger type, so that attrs sorted by type stays sorted. RFC 4271 5:
// "The sender of an UPDATE message SHOULD order path attributes within
// the UPDATE message in ascending order of attribute type."
func insertPathAttr(attrs []bgp.PathAttributeInterface, a bgp.PathAttributeInterface) []bgp.PathAttributeInterface {
	i := len(attrs)
	for j, b := range attrs {
		if b.GetType() > a.GetType() {
			i = j
			break
		}
	}
	return slices.Insert(attrs, i, a)
}

func (path *Path) GetNlri() bgp.NLRI {
	return path.OriginInfo().nlri
}

type PathAttrs []bgp.PathAttributeInterface

func (a PathAttrs) Len() int {
	return len(a)
}

func (a PathAttrs) Swap(i, j int) {
	a[i], a[j] = a[j], a[i]
}

func (a PathAttrs) Less(i, j int) bool {
	return a[i].GetType() < a[j].GetType()
}

// GetFullPathAttrs returns the path attributes together with a NEXT_HOP
// or MP_REACH_NLRI attribute that carries the next hop of the path. Use it
// where the attributes are shown to a user or written out, such as the API
// and MRT dumps. Use GetPathAttrs for the attributes that the path itself
// carries, which never include NEXT_HOP or MP_REACH_NLRI.
//
// An MP_REACH_NLRI carries the NLRI of the path only. A path with no next
// hop information, such as a received withdrawal, gets neither attribute.
func (path *Path) GetFullPathAttrs() []bgp.PathAttributeInterface {
	attrs := path.GetPathAttrs()
	if a := path.nexthopAttr(path.remoteID); a != nil {
		attrs = insertPathAttr(attrs, a)
	}
	return attrs
}

func (path *Path) GetPathAttrs() []bgp.PathAttributeInterface {
	deleted := NewBitmap(math.MaxUint8)
	modified := make(map[uint]bgp.PathAttributeInterface)
	p := path
	for {
		for _, t := range p.dels {
			deleted.Flag(uint(t))
		}
		if p.parent == nil {
			list := PathAttrs(make([]bgp.PathAttributeInterface, 0, len(p.pathAttrs)))
			// we assume that the original pathAttrs are
			// in order, that is, other bgp speakers send
			// attributes in order.
			for _, a := range p.pathAttrs {
				typ := uint(a.GetType())
				if m, ok := modified[typ]; ok {
					list = append(list, m)
					delete(modified, typ)
				} else if !deleted.GetFlag(typ) {
					list = append(list, a)
				}
			}
			if len(modified) > 0 {
				// Huh, some attributes were newly
				// added. So we need to sort...
				for _, m := range modified {
					list = append(list, m)
				}
				sort.Sort(list)
			}
			return list
		} else {
			for _, a := range p.pathAttrs {
				typ := uint(a.GetType())
				if _, ok := modified[typ]; !deleted.GetFlag(typ) && !ok {
					modified[typ] = a
				}
			}
		}
		p = p.parent
	}
}

func (path *Path) getPathAttr(typ bgp.BGPAttrType) bgp.PathAttributeInterface {
	p := path
	for {
		if slices.Contains(p.dels, typ) {
			return nil
		}
		for _, a := range p.pathAttrs {
			if a.GetType() == typ {
				return a
			}
		}
		if p.parent == nil {
			return nil
		}
		p = p.parent
	}
}

func (path *Path) setPathAttr(a bgp.PathAttributeInterface) {
	path.attrsHash.Store(0)
	if len(path.pathAttrs) == 0 {
		path.pathAttrs = []bgp.PathAttributeInterface{a}
	} else {
		for i, b := range path.pathAttrs {
			if a.GetType() == b.GetType() {
				path.pathAttrs[i] = a
				return
			}
		}
		path.pathAttrs = append(path.pathAttrs, a)
	}
}

func (path *Path) delPathAttr(typ bgp.BGPAttrType) {
	path.attrsHash.Store(0)
	if len(path.dels) == 0 {
		path.dels = []bgp.BGPAttrType{typ}
	} else {
		path.dels = append(path.dels, typ)
	}
}

// return Path's string representation
func (path *Path) String() string {
	s := bytes.NewBuffer(make([]byte, 0, 64))
	if path.IsEOR() {
		fmt.Fprintf(s, "{ %s EOR | src: %s }", path.GetFamily(), path.GetSource())
		return s.String()
	}
	fmt.Fprintf(s, "{ %s | ", path.GetPrefix())
	fmt.Fprintf(s, "src: %s", path.GetSource())
	fmt.Fprintf(s, ", nh: %s", path.GetNexthop())
	if path.IsNexthopInvalid {
		s.WriteString(" (not reachable)")
	}
	if path.IsWithdraw {
		s.WriteString(", withdraw")
	}
	s.WriteString(" }")
	return s.String()
}

// GetLocalKey identifies the path in the local BGP server.
func (path *Path) GetLocalKey() PathLocalKey {
	return PathLocalKey{
		PathDestLocalKey: path.GetDestLocalKey(),
		Id:               path.localID,
	}
}

// GetDestLocalKey identifies the path destination in the local BGP server.
func (path *Path) GetDestLocalKey() PathDestLocalKey {
	return PathDestLocalKey{
		Family: path.GetFamily(),
		Prefix: path.OriginInfo().nlriString,
	}
}

func (path *Path) GetPrefix() string {
	return path.GetNlri().String()
}

func (path *Path) GetAsPath() *bgp.PathAttributeAsPath {
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_AS_PATH)
	if attr != nil {
		return attr.(*bgp.PathAttributeAsPath)
	}
	return nil
}

// GetAsPathLen returns the number of AS_PATH
func (path *Path) GetAsPathLen() int {
	length := 0
	if aspath := path.GetAsPath(); aspath != nil {
		for _, as := range aspath.Value {
			length += as.ASLen()
		}
	}
	return length
}

func (path *Path) GetAsString() string {
	s := bytes.NewBuffer(make([]byte, 0, 64))
	if aspath := path.GetAsPath(); aspath != nil {
		return bgp.AsPathString(aspath)
	}
	return s.String()
}

func (path *Path) GetAsList() []uint32 {
	return path.getAsListOfSpecificType(true, true)
}

func (path *Path) GetAsSeqList() []uint32 {
	return path.getAsListOfSpecificType(true, false)
}

func (path *Path) getAsListOfSpecificType(getAsSeq, getAsSet bool) []uint32 {
	asList := []uint32{}
	if aspath := path.GetAsPath(); aspath != nil {
		for _, param := range aspath.Value {
			segType := param.GetType()
			if getAsSeq && segType == bgp.BGP_ASPATH_ATTR_TYPE_SEQ {
				asList = append(asList, param.GetAS()...)
				continue
			}
			if getAsSet && segType == bgp.BGP_ASPATH_ATTR_TYPE_SET {
				asList = append(asList, param.GetAS()...)
			} else {
				asList = append(asList, 0)
			}
		}
	}
	return asList
}

func (path *Path) GetLabelString() string {
	return bgp.LabelString(path.GetNlri())
}

// PrependAsn prepends AS number.
// This function updates the AS_PATH attribute as follows.
// (If the peer is in the confederation member AS,
//
//	replace AS_SEQUENCE in the following sentence with AS_CONFED_SEQUENCE.)
//	1) if the first path segment of the AS_PATH is of type
//	   AS_SEQUENCE, the local system prepends the specified AS num as
//	   the last element of the sequence (put it in the left-most
//	   position with respect to the position of  octets in the
//	   protocol message) the specified number of times.
//	   If the act of prepending will cause an overflow in the AS_PATH
//	   segment (i.e.,  more than 255 ASes),
//	   it SHOULD prepend a new segment of type AS_SEQUENCE
//	   and prepend its own AS number to this new segment.
//
//	2) if the first path segment of the AS_PATH is of other than type
//	   AS_SEQUENCE, the local system prepends a new path segment of type
//	   AS_SEQUENCE to the AS_PATH, including the specified AS number in
//	   that segment.
//
//	3) if the AS_PATH is empty, the local system creates a path
//	   segment of type AS_SEQUENCE, places the specified AS number
//	   into that segment, and places that segment into the AS_PATH.
func (path *Path) PrependAsn(asn uint32, repeat uint8, confed bool) {
	var segType uint8
	if confed {
		segType = bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ
	} else {
		segType = bgp.BGP_ASPATH_ATTR_TYPE_SEQ
	}

	original := path.GetAsPath()

	asns := make([]uint32, repeat)
	for i := range asns {
		asns[i] = asn
	}

	var asPath *bgp.PathAttributeAsPath
	if original == nil {
		asPath = bgp.NewPathAttributeAsPath([]bgp.AsPathParamInterface{})
	} else {
		asPath = cloneAsPath(original)
	}

	if len(asPath.Value) > 0 {
		param := asPath.Value[0]
		asList := param.GetAS()
		if param.GetType() == segType {
			// A segment holds at most 255 AS numbers. Put what does not
			// fit into a new segment in front.
			n := min(int(repeat), max(255-len(asList), 0))
			asPath.Value[0] = bgp.NewAs4PathParam(segType, slices.Concat(asns[:n], asList))
			asns = asns[n:]
		}
	}

	if len(asns) > 0 {
		p := bgp.NewAs4PathParam(segType, asns)
		asPath.Value = append([]bgp.AsPathParamInterface{p}, asPath.Value...)
	}
	path.setPathAttr(asPath)
}

func isPrivateAS(as uint32) bool {
	return 64512 <= as && as <= 65534 || 4200000000 <= as && as <= 4294967294
}

func (path *Path) RemovePrivateAS(localAS uint32, option oc.RemovePrivateAsOption) {
	original := path.GetAsPath()
	if original == nil {
		return
	}
	switch option {
	case oc.REMOVE_PRIVATE_AS_OPTION_ALL, oc.REMOVE_PRIVATE_AS_OPTION_REPLACE:
		newASParams := make([]bgp.AsPathParamInterface, 0, len(original.Value))
		for _, param := range original.Value {
			asList := param.GetAS()
			newASParam := make([]uint32, 0, len(asList))
			for _, as := range asList {
				if isPrivateAS(as) {
					if option == oc.REMOVE_PRIVATE_AS_OPTION_REPLACE {
						newASParam = append(newASParam, localAS)
					}
				} else {
					newASParam = append(newASParam, as)
				}
			}
			if len(newASParam) > 0 {
				newASParams = append(newASParams, bgp.NewAs4PathParam(param.GetType(), newASParam))
			}
		}
		path.setPathAttr(bgp.NewPathAttributeAsPath(newASParams))
	}
}

func (path *Path) removeConfedAs() {
	original := path.GetAsPath()
	if original == nil {
		return
	}
	newAsParams := make([]bgp.AsPathParamInterface, 0, len(original.Value))
	for _, param := range original.Value {
		switch param.GetType() {
		case bgp.BGP_ASPATH_ATTR_TYPE_SEQ, bgp.BGP_ASPATH_ATTR_TYPE_SET:
			newAsParams = append(newAsParams, param)
		}
	}
	path.setPathAttr(bgp.NewPathAttributeAsPath(newAsParams))
}

func (path *Path) ReplaceAS(localAS, peerAS uint32) *Path {
	original := path.GetAsPath()
	if original == nil {
		return path
	}
	newASParams := make([]bgp.AsPathParamInterface, 0, len(original.Value))
	changed := false
	for _, param := range original.Value {
		segType := param.GetType()
		asList := param.GetAS()
		newASParam := make([]uint32, 0, len(asList))
		for _, as := range asList {
			if as == peerAS {
				as = localAS
				changed = true
			}
			newASParam = append(newASParam, as)
		}
		newASParams = append(newASParams, bgp.NewAs4PathParam(segType, newASParam))
	}
	if changed {
		path = path.Clone(path.IsWithdraw)
		path.setPathAttr(bgp.NewPathAttributeAsPath(newASParams))
	}
	return path
}

func (path *Path) GetCommunities() []uint32 {
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES); attr != nil {
		return attr.(*bgp.PathAttributeCommunities).Value
	}
	return nil
}

// SetCommunities adds or replaces communities with new ones.
// If the length of communities is 0 and doReplace is true, it clears communities.
func (path *Path) SetCommunities(communities []uint32, doReplace bool) {
	if len(communities) == 0 && doReplace {
		// clear communities
		path.delPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
		return
	}

	newList := make([]uint32, 0)
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
	if attr != nil {
		c := attr.(*bgp.PathAttributeCommunities)
		if doReplace {
			newList = append(newList, communities...)
		} else {
			newList = append(newList, c.Value...)
			newList = append(newList, communities...)
		}
	} else {
		newList = append(newList, communities...)
	}
	path.setPathAttr(bgp.NewPathAttributeCommunities(newList))
}

// RemoveCommunities removes specific communities.
// If the length of communities is 0, it does nothing.
// If all communities are removed, it removes Communities path attribute itself.
func (path *Path) RemoveCommunities(communities []uint32) int {
	if len(communities) == 0 {
		// do nothing
		return 0
	}

	find := func(val uint32) bool {
		return slices.Contains(communities, val)
	}

	count := 0
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
	if attr != nil {
		newList := make([]uint32, 0)
		c := attr.(*bgp.PathAttributeCommunities)

		for _, value := range c.Value {
			if find(value) {
				count += 1
			} else {
				newList = append(newList, value)
			}
		}

		if len(newList) != 0 {
			path.setPathAttr(bgp.NewPathAttributeCommunities(newList))
		} else {
			path.delPathAttr(bgp.BGP_ATTR_TYPE_COMMUNITIES)
		}
	}
	return count
}

func (path *Path) GetExtCommunities() []bgp.ExtendedCommunityInterface {
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES); attr != nil {
		return attr.(*bgp.PathAttributeExtendedCommunities).Value
	}
	return nil
}

func (path *Path) SetExtCommunities(exts []bgp.ExtendedCommunityInterface, doReplace bool) {
	if len(exts) == 0 {
		if doReplace {
			// RFC7606 Section 7.14 considers the attribute malformed unless
			// its length is a non-zero multiple of 8, so drop it rather than
			// advertising an empty one.
			path.delPathAttr(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES)
		}
		return
	}
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES); attr != nil && !doReplace {
		// Concat rather than append, so growing this path's list cannot write
		// into the backing array of an attribute shared with another path.
		exts = slices.Concat(attr.(*bgp.PathAttributeExtendedCommunities).Value, exts)
	}
	path.setPathAttr(bgp.NewPathAttributeExtendedCommunities(exts))
}

func (path *Path) GetIP6ExtCommunities() []bgp.ExtendedCommunityInterface {
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_IP6_EXTENDED_COMMUNITIES); attr != nil {
		return attr.(*bgp.PathAttributeIP6ExtendedCommunities).Value
	}
	return nil
}

// SetIP6ExtCommunities is the counterpart of SetExtCommunities for the IPv6
// Address Specific Extended Community attribute (RFC5701 Section 3). The two
// attributes carry communities of different sizes and neither reaches into the
// other.
func (path *Path) SetIP6ExtCommunities(exts []bgp.ExtendedCommunityInterface, doReplace bool) {
	if len(exts) == 0 {
		if doReplace {
			path.delPathAttr(bgp.BGP_ATTR_TYPE_IP6_EXTENDED_COMMUNITIES)
		}
		return
	}
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_IP6_EXTENDED_COMMUNITIES); attr != nil && !doReplace {
		exts = slices.Concat(attr.(*bgp.PathAttributeIP6ExtendedCommunities).Value, exts)
	}
	path.setPathAttr(bgp.NewPathAttributeIP6ExtendedCommunities(exts))
}

func (path *Path) GetRouteTargets() []bgp.ExtendedCommunityInterface {
	rts := make([]bgp.ExtendedCommunityInterface, 0)
	for _, ec := range path.GetExtCommunities() {
		if t, st := ec.GetTypes(); t <= bgp.EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC && st == bgp.EC_SUBTYPE_ROUTE_TARGET {
			rts = append(rts, ec)
		}
	}
	return rts
}

func (path *Path) GetLargeCommunities() []*bgp.LargeCommunity {
	if a := path.getPathAttr(bgp.BGP_ATTR_TYPE_LARGE_COMMUNITY); a != nil {
		return a.(*bgp.PathAttributeLargeCommunities).Values
	}
	return nil
}

func (path *Path) SetLargeCommunities(cs []*bgp.LargeCommunity, doReplace bool) {
	if len(cs) == 0 && doReplace {
		// clear large communities
		path.delPathAttr(bgp.BGP_ATTR_TYPE_LARGE_COMMUNITY)
		return
	}

	a := path.getPathAttr(bgp.BGP_ATTR_TYPE_LARGE_COMMUNITY)
	if a == nil || doReplace {
		path.setPathAttr(bgp.NewPathAttributeLargeCommunities(cs))
	} else {
		l := a.(*bgp.PathAttributeLargeCommunities).Values
		path.setPathAttr(bgp.NewPathAttributeLargeCommunities(append(l, cs...)))
	}
}

func (path *Path) GetMed() (uint32, error) {
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC)
	if attr == nil {
		return 0, ErrNoMedPathAttr
	}
	return attr.(*bgp.PathAttributeMultiExitDisc).Value, nil
}

// SetMed replace, add or subtraction med with new ones.
func (path *Path) SetMed(med int64, doReplace bool) error {
	parseMed := func(orgMed uint32, med int64, doReplace bool) (*bgp.PathAttributeMultiExitDisc, error) {
		if doReplace {
			return bgp.NewPathAttributeMultiExitDisc(uint32(med)), nil
		}

		medVal := int64(orgMed) + med
		if medVal < 0 {
			return nil, fmt.Errorf("med value invalid. it's underflow threshold: %v", medVal)
		} else if medVal > int64(math.MaxUint32) {
			return nil, fmt.Errorf("med value invalid. it's overflow threshold: %v", medVal)
		}

		return bgp.NewPathAttributeMultiExitDisc(uint32(int64(orgMed) + med)), nil
	}

	m := uint32(0)
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_MULTI_EXIT_DISC); attr != nil {
		m = attr.(*bgp.PathAttributeMultiExitDisc).Value
	}
	newMed, err := parseMed(m, med, doReplace)
	if err != nil {
		return err
	}
	path.setPathAttr(newMed)
	return nil
}

func (path *Path) RemoveLocalPref() {
	if path.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF) != nil {
		path.delPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)
	}
}

func (path *Path) GetOriginatorID() netip.Addr {
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGINATOR_ID); attr != nil {
		return attr.(*bgp.PathAttributeOriginatorId).Value
	}
	return netip.Addr{}
}

func (path *Path) GetClusterList() []netip.Addr {
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_CLUSTER_LIST); attr != nil {
		return attr.(*bgp.PathAttributeClusterList).Value
	}
	return nil
}

func (path *Path) GetOrigin() (uint8, error) {
	if attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_ORIGIN); attr != nil {
		return attr.(*bgp.PathAttributeOrigin).Value, nil
	}
	return 0, fmt.Errorf("no origin path attr")
}

func (path *Path) GetLocalPref() (uint32, error) {
	lp := uint32(DEFAULT_LOCAL_PREF)
	attr := path.getPathAttr(bgp.BGP_ATTR_TYPE_LOCAL_PREF)
	if attr != nil {
		lp = attr.(*bgp.PathAttributeLocalPref).Value
	}
	return lp, nil
}

func (lhs *Path) EqualBySourceAndPathID(rhs *Path) bool {
	if rhs == nil {
		return false
	}
	if lhs == rhs {
		return true
	}

	if !lhs.GetSource().Equal(rhs.GetSource()) {
		return false
	}

	return lhs.remoteID == rhs.remoteID
}

func (lhs *Path) Equal(rhs *Path) bool {
	if rhs == nil {
		return false
	}
	if lhs == rhs {
		return true
	}

	lhsPathAttrs := lhs.GetPathAttrs()
	rhsPathAttrs := rhs.GetPathAttrs()
	// comparing by length first as it's quite fast (with golang slice)
	// and easy to know if paths are different
	if len(lhsPathAttrs) == 0 && len(rhsPathAttrs) == 0 && lhs.nh == nil && rhs.nh == nil {
		return lhs.EqualBySourceAndPathID(rhs)
	}

	if len(lhsPathAttrs) != len(rhsPathAttrs) {
		return false
	}

	if !lhs.GetSource().Equal(rhs.GetSource()) {
		return false
	}
	// The idea here is to calculate the hash of the attributes on demand
	lhsHash := lhs.attrsHash.Load()
	rhsHash := rhs.attrsHash.Load()
	if lhsHash > 0 && rhsHash > 0 { // avoid unnecessary hash calculation
		if lhsHash != rhsHash {
			return false
		}
	} else {
		// slow path comparison, could happen as attributes flags is not part of the hash
		for t, a := range lhsPathAttrs {
			b := rhsPathAttrs[t]
			if a.GetType() != b.GetType() {
				return false
			}
			if a.Len() != b.Len() {
				return false
			}
			if a.GetFlags() != b.GetFlags() {
				return false
			}
		}
		// really slow path comparison, if hash not been calculated yet
		if lhs.GetHash() != rhs.GetHash() {
			return false
		}
	}

	// The next hops and the NLRI are not path attributes, so the hash does
	// not cover them and they are compared here. The NLRI comparison uses
	// serialized bytes because it must cover fields outside the route key
	// (e.g. the TEID of a MUP type-1 session transformed route), which
	// nlri.String() does not include.
	if lhs.nexthops() != rhs.nexthops() {
		return false
	}
	lhsNlri, rhsNlri := lhs.GetNlri(), rhs.GetNlri()
	if lhsNlri == nil || rhsNlri == nil {
		return lhsNlri == nil && rhsNlri == nil
	}
	lhsNlriBytes, _ := lhsNlri.Serialize()
	rhsNlriBytes, _ := rhsNlri.Serialize()
	return bytes.Equal(lhsNlriBytes, rhsNlriBytes)
}

func (path *Path) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Nlri       bgp.NLRI                     `json:"nlri"`
		PathAttrs  []bgp.PathAttributeInterface `json:"attrs"`
		Age        int64                        `json:"age"`
		Withdrawal bool                         `json:"withdrawal,omitempty"`
		Validation string                       `json:"validation,omitempty"`
		SourceID   net.IP                       `json:"source-id,omitempty"`
		NeighborIP netip.Addr                   `json:"neighbor-ip,omitempty"`
		Stale      bool                         `json:"stale,omitempty"`
		UUID       string                       `json:"uuid,omitempty"`
		ID         uint32                       `json:"id,omitempty"`
	}{
		Nlri:       path.GetNlri(),
		PathAttrs:  path.GetFullPathAttrs(),
		Age:        path.GetTimestamp().Unix(),
		Withdrawal: path.IsWithdraw,
		SourceID:   path.GetSource().ID.AsSlice(),
		NeighborIP: path.GetSource().Address,
		Stale:      path.IsStale(),
		ID:         path.remoteID,
	})
}

// Return > 0 if lhs is preferred over the rhs
// Return 0 if they are equal
// Return < 0 if rhs is preferred over the lhs
func (lhs *Path) Compare(rhs *Path) int {
	if s1, s2 := lhs.IsLLGRStale(), rhs.IsLLGRStale(); s1 != s2 {
		if s1 {
			return -1
		}
		return 1
	}

	if lhs.IsLocal() && !rhs.IsLocal() {
		return 1
	} else if !lhs.IsLocal() && rhs.IsLocal() {
		return -1
	}

	if !lhs.IsIBGP() && rhs.IsIBGP() {
		return 1
	} else if lhs.IsIBGP() && !rhs.IsIBGP() {
		return -1
	}

	lp1, _ := lhs.GetLocalPref()
	lp2, _ := rhs.GetLocalPref()
	if lp1 != lp2 {
		return int(lp1) - int(lp2)
	}

	l1 := lhs.GetAsPathLen()
	l2 := rhs.GetAsPathLen()
	if l1 != l2 {
		return l2 - l1
	}

	o1, _ := lhs.GetOrigin()
	o2, _ := rhs.GetOrigin()
	if o1 != o2 {
		return int(o2) - int(o1)
	}

	m1, _ := lhs.GetMed()
	m2, _ := rhs.GetMed()
	return int(m2) - int(m1)
}

func (v *Vrf) ToGlobalPath(path *Path) error {
	nlri := path.GetNlri()
	nh := path.GetNexthop()

	switch rf := path.GetFamily(); rf {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		n := nlri.(*bgp.IPAddrPrefix)
		path.OriginInfo().nlri, _ = bgp.NewLabeledVPNIPAddrPrefix(n.Prefix, *bgp.NewMPLSLabelStack(v.MplsLabel), v.Rd)
		if rf == bgp.RF_IPv4_UC {
			path.family = bgp.RF_IPv4_VPN
		} else {
			path.family = bgp.RF_IPv6_VPN
		}
	case bgp.RF_FS_IPv4_UC, bgp.RF_FS_IPv6_UC:
		n := nlri.(*bgp.FlowSpecNLRI)
		if rf == bgp.RF_FS_IPv4_UC {
			path.family = bgp.RF_FS_IPv4_VPN
		} else {
			path.family = bgp.RF_FS_IPv6_VPN
		}
		path.OriginInfo().nlri, _ = bgp.NewFlowSpecVPN(path.family, v.Rd, n.Value)
	case bgp.RF_EVPN:
		n := nlri.(*bgp.EVPNNLRI)
		switch n.RouteType {
		case bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
			n.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute).RD = v.Rd
		case bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG:
			n.RouteTypeData.(*bgp.EVPNMulticastEthernetTagRoute).RD = v.Rd
		}
	case bgp.RF_MUP_IPv4, bgp.RF_MUP_IPv6:
		n := nlri.(*bgp.MUPNLRI)
		switch n.RouteType {
		case bgp.MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY:
			n.RouteTypeData.(*bgp.MUPInterworkSegmentDiscoveryRoute).RD = v.Rd
		case bgp.MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY:
			n.RouteTypeData.(*bgp.MUPDirectSegmentDiscoveryRoute).RD = v.Rd
		case bgp.MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED:
			n.RouteTypeData.(*bgp.MUPType1SessionTransformedRoute).RD = v.Rd
		case bgp.MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED:
			n.RouteTypeData.(*bgp.MUPType2SessionTransformedRoute).RD = v.Rd
		}
	default:
		return fmt.Errorf("unsupported route family for vrf: %s", rf)
	}
	// The NLRI now carries the RD, so the string that the destination keys
	// such as GetDestLocalKey are built from has to follow it.
	path.OriginInfo().nlriString = path.OriginInfo().nlri.String()
	path.SetExtCommunities(v.ExportRt, false)
	path.SetNexthop(nh)
	return nil
}

func (p *Path) ToGlobal(vrf *Vrf) *Path {
	nlri := p.GetNlri()
	nh := p.GetNexthop()
	var newFamily bgp.Family
	switch rf := p.GetFamily(); rf {
	case bgp.RF_IPv4_UC, bgp.RF_IPv6_UC:
		n := nlri.(*bgp.IPAddrPrefix)
		nlri, _ = bgp.NewLabeledVPNIPAddrPrefix(n.Prefix, *bgp.NewMPLSLabelStack(vrf.MplsLabel), vrf.Rd)
		if rf == bgp.RF_IPv4_UC {
			newFamily = bgp.RF_IPv4_VPN
		} else {
			newFamily = bgp.RF_IPv6_VPN
		}
	case bgp.RF_EVPN:
		n := nlri.(*bgp.EVPNNLRI)
		switch n.RouteType {
		case bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
			old := n.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
			new := &bgp.EVPNMacIPAdvertisementRoute{
				RD:               vrf.Rd,
				ESI:              old.ESI,
				ETag:             old.ETag,
				MacAddressLength: old.MacAddressLength,
				MacAddress:       old.MacAddress,
				IPAddressLength:  old.IPAddressLength,
				IPAddress:        old.IPAddress,
				Labels:           old.Labels,
			}
			nlri = bgp.NewEVPNNLRI(n.RouteType, new)
		case bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG:
			old := n.RouteTypeData.(*bgp.EVPNMulticastEthernetTagRoute)
			new := &bgp.EVPNMulticastEthernetTagRoute{
				RD:              vrf.Rd,
				ETag:            old.ETag,
				IPAddressLength: old.IPAddressLength,
				IPAddress:       old.IPAddress,
			}
			nlri = bgp.NewEVPNNLRI(n.RouteType, new)
		}
		newFamily = rf
	case bgp.RF_MUP_IPv4, bgp.RF_MUP_IPv6:
		n := nlri.(*bgp.MUPNLRI)
		switch n.RouteType {
		case bgp.MUP_ROUTE_TYPE_INTERWORK_SEGMENT_DISCOVERY:
			old := n.RouteTypeData.(*bgp.MUPInterworkSegmentDiscoveryRoute)
			nlri = bgp.NewMUPInterworkSegmentDiscoveryRoute(vrf.Rd, old.Prefix)
		case bgp.MUP_ROUTE_TYPE_DIRECT_SEGMENT_DISCOVERY:
			old := n.RouteTypeData.(*bgp.MUPDirectSegmentDiscoveryRoute)
			nlri = bgp.NewMUPDirectSegmentDiscoveryRoute(vrf.Rd, old.Address)
		case bgp.MUP_ROUTE_TYPE_TYPE_1_SESSION_TRANSFORMED:
			old := n.RouteTypeData.(*bgp.MUPType1SessionTransformedRoute)
			nlri = bgp.NewMUPType1SessionTransformedRoute(vrf.Rd, old.Prefix, old.TEID, old.QFI, old.EndpointAddress, old.SourceAddress, old.TLVs...)
		case bgp.MUP_ROUTE_TYPE_TYPE_2_SESSION_TRANSFORMED:
			old := n.RouteTypeData.(*bgp.MUPType2SessionTransformedRoute)
			nlri = bgp.NewMUPType2SessionTransformedRoute(vrf.Rd, old.EndpointAddressLength, old.EndpointAddress, old.TEID, old.TLVs...)
		}
		newFamily = rf
	default:
		return p
	}
	path := NewPath(newFamily, p.OriginInfo().source, bgp.PathNLRI{NLRI: nlri}, p.IsWithdraw, p.GetPathAttrs(), p.GetTimestamp(), false)
	path.SetExtCommunities(vrf.ExportRt, false)
	path.localID = p.localID
	path.remoteID = p.remoteID
	if p.nh != nil {
		path.setNexthops(Nexthops{global: nh})
	}
	return path
}

func (p *Path) ToLocal() *Path {
	var newFamily bgp.Family
	nlri := p.GetNlri()
	f := p.GetFamily()
	switch f {
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		n := nlri.(*bgp.LabeledVPNIPAddrPrefix)
		nlri, _ = bgp.NewIPAddrPrefix(n.Prefix)
		if f == bgp.RF_IPv4_VPN {
			newFamily = bgp.RF_IPv4_UC
		} else {
			newFamily = bgp.RF_IPv6_UC
		}
	case bgp.RF_FS_IPv4_VPN, bgp.RF_FS_IPv6_VPN:
		n := nlri.(*bgp.FlowSpecNLRI)
		newFamily = bgp.RF_FS_IPv4_UC
		if f == bgp.RF_FS_IPv6_VPN {
			newFamily = bgp.RF_FS_IPv6_UC
		}
		nlri, _ = bgp.NewFlowSpecUnicast(newFamily, n.Value)
	default:
		return p
	}
	path := NewPath(newFamily, p.OriginInfo().source, bgp.PathNLRI{NLRI: nlri}, p.IsWithdraw, p.GetPathAttrs(), p.GetTimestamp(), false)
	switch f {
	case bgp.RF_IPv4_VPN, bgp.RF_IPv6_VPN:
		path.delPathAttr(bgp.BGP_ATTR_TYPE_EXTENDED_COMMUNITIES)
	case bgp.RF_FS_IPv4_VPN, bgp.RF_FS_IPv6_VPN:
		extcomms := path.GetExtCommunities()
		newExtComms := make([]bgp.ExtendedCommunityInterface, 0, len(extcomms))
		for _, extComm := range extcomms {
			_, subType := extComm.GetTypes()
			if subType == bgp.EC_SUBTYPE_ROUTE_TARGET {
				continue
			}
			newExtComms = append(newExtComms, extComm)
		}
		path.SetExtCommunities(newExtComms, true)
	}

	path.IsNexthopInvalid = p.IsNexthopInvalid
	path.localID = p.localID
	path.remoteID = p.remoteID
	path.nh = p.nh
	return path
}

// updateHash must stay in sync with the shared per-UPDATE hash in
// ProcessMessage (table_manager.go) so that lazily and eagerly hashed
// paths compare equal. The hash covers the path attributes only, not the
// next hops and the NLRI, so it does not change when the next hop is
// rewritten for a peer. The UPDATE packers mix the next hops in, and
// Equal compares the next hops and the NLRI itself.
func (p *Path) updateHash() {
	total := bytes.NewBuffer(make([]byte, 0))
	for _, a := range p.GetPathAttrs() {
		d, _ := a.Serialize()
		total.Write(d)
	}
	p.attrsHash.Store(farm.Hash64(total.Bytes()))
}

func (p *Path) SetHash(v uint64) {
	p.attrsHash.Store(v)
}

// GetHash returns the hash value of the path attributes.
func (p *Path) GetHash() uint64 {
	if p.attrsHash.Load() == 0 {
		p.updateHash()
	}
	return p.attrsHash.Load()
}

func (p *Path) SetSource(peerInfo *PeerInfo) {
	if p.info != nil {
		p.info.source = peerInfo
	}
}

func (p *Path) LocalID() uint32 {
	return p.localID
}

func (p *Path) RemoteID() uint32 {
	return p.remoteID
}

func nlriToIPNet(nlri bgp.NLRI) *net.IPNet {
	switch T := nlri.(type) {
	case *bgp.IPAddrPrefix:
		return &net.IPNet{
			IP:   T.Prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(T.Prefix.Bits(), T.Prefix.Addr().BitLen()),
		}
	case *bgp.LabeledIPAddrPrefix:
		return &net.IPNet{
			IP:   T.Prefix.Masked().Addr().AsSlice(),
			Mask: net.CIDRMask(T.Prefix.Bits(), T.Prefix.Addr().BitLen()),
		}
	case *bgp.LabeledVPNIPAddrPrefix:
		return &net.IPNet{
			IP:   T.Prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(T.Prefix.Bits(), T.Prefix.Addr().BitLen()),
		}
	}
	return nil
}

func nlriToPrefix(nlri bgp.NLRI) netip.Prefix {
	switch T := nlri.(type) {
	case *bgp.IPAddrPrefix:
		return T.Prefix
	case *bgp.LabeledIPAddrPrefix:
		return T.Prefix
	case *bgp.LabeledVPNIPAddrPrefix:
		return T.Prefix
	case *bgp.RouteTargetMembershipNLRI:
		var addr [16]byte
		binary.BigEndian.PutUint32(addr[:4], T.AS)
		rtKey, err := T.RouteTargetKey()
		if err != nil {
			return netip.Prefix{}
		}
		binary.BigEndian.PutUint64(addr[4:12], rtKey)
		return netip.PrefixFrom(netip.AddrFrom16(addr), int(T.Length))
	case *bgp.EVPNNLRI:
		switch r := T.RouteTypeData.(type) {
		case *bgp.EVPNIPPrefixRoute:
			return netip.PrefixFrom(r.IPPrefix, int(r.IPPrefixLength))
		case *bgp.EVPNMacIPAdvertisementRoute:
			if r.IPAddress.IsValid() {
				return netip.PrefixFrom(r.IPAddress, r.IPAddress.BitLen())
			}
		}
	}
	return netip.Prefix{}
}
