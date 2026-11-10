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
	"net/netip"
	"reflect"
	"slices"

	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/segmentio/fasthash/fnv1a"
)

// maxUpdateMessageLength returns the per-UPDATE serialisation budget
// the packer should fill before emitting a message. When the caller
// signalled the RFC 8654 Extended Message Capability via a
// MarshallingOption, the cap rises from 4096 to 65535 octets - UPDATE
// is one of the message types Section 6 of the RFC explicitly extends.
func maxUpdateMessageLength(options []*bgp.MarshallingOption) int {
	if bgp.IsExtendedMessageSerialization(options) {
		return bgp.BGP_MAX_EXTENDED_MESSAGE_LENGTH
	}
	return bgp.BGP_MAX_MESSAGE_LENGTH
}

func UpdatePathAttrs2ByteAs(msg *bgp.BGPUpdate) {
	ps := msg.PathAttributes
	msg.PathAttributes = make([]bgp.PathAttributeInterface, len(ps))
	copy(msg.PathAttributes, ps)
	var asAttr *bgp.PathAttributeAsPath
	idx := 0
	for i, attr := range msg.PathAttributes {
		if a, ok := attr.(*bgp.PathAttributeAsPath); ok {
			asAttr = a
			idx = i
			break
		}
	}

	if asAttr == nil {
		return
	}

	as4Params := make([]*bgp.As4PathParam, 0, len(asAttr.Value))
	as2Params := make([]bgp.AsPathParamInterface, 0, len(asAttr.Value))
	mkAs4 := false
	for _, param := range asAttr.Value {
		segType := param.GetType()
		asList := param.GetAS()
		as2Path := make([]uint16, 0, len(asList))
		for _, as := range asList {
			if as > 1<<16-1 {
				mkAs4 = true
				as2Path = append(as2Path, bgp.AS_TRANS)
			} else {
				as2Path = append(as2Path, uint16(as))
			}
		}
		as2Params = append(as2Params, bgp.NewAsPathParam(segType, as2Path))

		// RFC 6793 4.2.2 Generating Updates
		//
		// Whenever the AS path information contains the AS_CONFED_SEQUENCE or
		// AS_CONFED_SET path segment, the NEW BGP speaker MUST exclude such
		// path segments from the AS4_PATH attribute being constructed.
		switch segType {
		case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET:
			// pass
		default:
			if as4param, ok := param.(*bgp.As4PathParam); ok {
				as4Params = append(as4Params, as4param)
			}
		}
	}
	msg.PathAttributes[idx] = bgp.NewPathAttributeAsPath(as2Params)
	if mkAs4 {
		msg.PathAttributes = append(msg.PathAttributes, bgp.NewPathAttributeAs4Path(as4Params))
	}
}

// DiscardAs4Attrs removes AS4_PATH and AS4_AGGREGATOR from an UPDATE
// received from a NEW BGP speaker. RFC 6793 Section 4.1 says they MUST NOT be
// carried between NEW BGP speakers and MUST be discarded when received.
func DiscardAs4Attrs(msg *bgp.BGPUpdate) {
	msg.PathAttributes = slices.DeleteFunc(msg.PathAttributes, func(attr bgp.PathAttributeInterface) bool {
		switch attr.(type) {
		case *bgp.PathAttributeAs4Path, *bgp.PathAttributeAs4Aggregator:
			return true
		}
		return false
	})
}

func UpdatePathAttrs4ByteAs(logger *slog.Logger, msg *bgp.BGPUpdate) {
	var asAttr *bgp.PathAttributeAsPath
	var as4Attr *bgp.PathAttributeAs4Path
	asAttrPos := 0
	as4AttrPos := 0
	for i, attr := range msg.PathAttributes {
		switch a := attr.(type) {
		case *bgp.PathAttributeAsPath:
			asAttr = a
			for j, param := range asAttr.Value {
				as2Param, ok := param.(*bgp.AsPathParam)
				if ok {
					asPath := make([]uint32, 0, len(as2Param.AS))
					for _, as := range as2Param.AS {
						asPath = append(asPath, uint32(as))
					}
					as4Param := bgp.NewAs4PathParam(as2Param.Type, asPath)
					asAttr.Value[j] = as4Param
				}
			}
			asAttrPos = i
			msg.PathAttributes[i] = asAttr
		case *bgp.PathAttributeAs4Path:
			as4AttrPos = i
			as4Attr = a
		}
	}

	if as4Attr != nil {
		msg.PathAttributes = append(msg.PathAttributes[:as4AttrPos], msg.PathAttributes[as4AttrPos+1:]...)
		// Adjust asAttrPos if AS4_PATH was before AS_PATH
		// (AS4_PATH removal shifts the indices of subsequent attributes)
		if as4AttrPos < asAttrPos {
			asAttrPos--
		}
	}

	if asAttr == nil || as4Attr == nil {
		return
	}

	asLen := 0
	asConfedLen := 0
	asParams := make([]bgp.AsPathParamInterface, 0, len(asAttr.Value))
	for _, param := range asAttr.Value {
		asLen += param.ASLen()
		switch param.GetType() {
		case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET:
			asConfedLen++
		case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
			asConfedLen += len(param.GetAS())
		}
		asParams = append(asParams, param)
	}

	as4Len := 0
	var as4Params []bgp.AsPathParamInterface
	if as4Attr != nil {
		as4Params = make([]bgp.AsPathParamInterface, 0, len(as4Attr.Value))
		for _, p := range as4Attr.Value {
			// RFC 6793 6. Error Handling
			//
			// the path segment types AS_CONFED_SEQUENCE and AS_CONFED_SET [RFC5065]
			// MUST NOT be carried in the AS4_PATH attribute of an UPDATE message.
			// A NEW BGP speaker that receives these path segment types in the AS4_PATH
			// attribute of an UPDATE message from an OLD BGP speaker MUST discard
			// these path segments, adjust the relevant attribute fields accordingly,
			// and continue processing the UPDATE message.
			// This case SHOULD be logged locally for analysis.
			switch p.Type {
			case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET:
				typ := "CONFED_SEQ"
				if p.Type == bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET {
					typ = "CONFED_SET"
				}
				logger.Warn(fmt.Sprintf("AS4_PATH contains %s segment %s. ignore", typ, p.String()),
					slog.String("Topic", "Table"))
				continue
			}
			as4Len += p.ASLen()
			as4Params = append(as4Params, p)
		}
	}

	if asLen+asConfedLen < as4Len {
		logger.Warn("AS4_PATH is longer than AS_PATH. ignore AS4_PATH",
			slog.String("Topic", "Table"))
		return
	}

	keepNum := asLen + asConfedLen - as4Len

	newParams := make([]bgp.AsPathParamInterface, 0, len(asAttr.Value))
	for _, param := range asParams {
		if keepNum <= 0 {
			break
		}
		// keepNum counts confederation segments too, so consume them the
		// same way here.
		n := param.ASLen()
		switch param.GetType() {
		case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET:
			n = 1
		case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
			n = len(param.GetAS())
		}
		if n <= keepNum {
			newParams = append(newParams, param)
			keepNum -= n
		} else {
			// only a sequence reaches here
			newParams = append(newParams, bgp.NewAs4PathParam(param.GetType(), param.GetAS()[:keepNum]))
			keepNum = 0
		}
	}

	for _, param := range as4Params {
		if len(newParams) == 0 {
			newParams = append(newParams, param)
			continue
		}
		lastParam := newParams[len(newParams)-1]
		lastParamAS := lastParam.GetAS()
		paramType := param.GetType()
		paramAS := param.GetAS()
		if paramType == lastParam.GetType() && paramType == bgp.BGP_ASPATH_ATTR_TYPE_SEQ {
			if len(lastParamAS)+len(paramAS) > 255 {
				newParams[len(newParams)-1] = bgp.NewAs4PathParam(paramType, append(lastParamAS, paramAS[:255-len(lastParamAS)]...))
				newParams = append(newParams, bgp.NewAs4PathParam(paramType, paramAS[255-len(lastParamAS):]))
			} else {
				newParams[len(newParams)-1] = bgp.NewAs4PathParam(paramType, append(lastParamAS, paramAS...))
			}
		} else {
			newParams = append(newParams, param)
		}
	}

	newIntfParams := make([]bgp.AsPathParamInterface, 0, len(asAttr.Value))
	newIntfParams = append(newIntfParams, newParams...)

	msg.PathAttributes[asAttrPos] = bgp.NewPathAttributeAsPath(newIntfParams)
}

func UpdatePathAggregator2ByteAs(msg *bgp.BGPUpdate) {
	as := uint32(0)
	var addr netip.Addr
	for i, attr := range msg.PathAttributes {
		switch agg := attr.(type) {
		case *bgp.PathAttributeAggregator:
			addr = agg.Value.Address
			if agg.Value.AS > 1<<16-1 {
				as = agg.Value.AS
				attr, _ := bgp.NewPathAttributeAggregator(uint16(bgp.AS_TRANS), addr)
				msg.PathAttributes[i] = attr
			} else {
				attr, _ := bgp.NewPathAttributeAggregator(uint16(agg.Value.AS), addr)
				msg.PathAttributes[i] = attr
			}
		}
	}
	if as != 0 {
		attr, _ := bgp.NewPathAttributeAs4Aggregator(as, addr)
		msg.PathAttributes = append(msg.PathAttributes, attr)
	}
}

// UpdatePathAggregator4ByteAs merges AS4_AGGREGATOR into AGGREGATOR. It must
// be called before UpdatePathAttrs4ByteAs because it can remove AS4_PATH.
// RFC 6793 Section 4.2.3 says:
//
//	When both of the attributes are received, if the AS number in the
//	AGGREGATOR attribute is not AS_TRANS, then:
//
//	   -  the AS4_AGGREGATOR attribute and the AS4_PATH attribute SHALL
//	      be ignored,
//
// RFC 6793 does not cover AS4_AGGREGATOR without AGGREGATOR. A NEW BGP
// speaker never sends it that way, so drop AS4_AGGREGATOR and keep the
// UPDATE. Section 6 handles a malformed AS4_AGGREGATOR with "attribute
// discard" too.
func UpdatePathAggregator4ByteAs(msg *bgp.BGPUpdate) {
	var aggAttr *bgp.PathAttributeAggregator
	var agg4Attr *bgp.PathAttributeAs4Aggregator
	for _, attr := range msg.PathAttributes {
		switch agg := attr.(type) {
		case *bgp.PathAttributeAggregator:
			attr := agg
			switch attr.Value.Askind {
			case reflect.Uint16:
				aggAttr = attr
				aggAttr.Value.Askind = reflect.Uint32
			case reflect.Uint32:
				aggAttr = attr
			}
		case *bgp.PathAttributeAs4Aggregator:
			agg4Attr = agg
		}
	}
	if agg4Attr == nil {
		return
	}

	ignoreAs4Path := false
	switch {
	case aggAttr == nil:
	case aggAttr.Value.AS != bgp.AS_TRANS:
		ignoreAs4Path = true
	default:
		aggAttr.Value.AS = agg4Attr.Value.AS
	}
	msg.PathAttributes = slices.DeleteFunc(msg.PathAttributes, func(attr bgp.PathAttributeInterface) bool {
		switch attr.(type) {
		case *bgp.PathAttributeAs4Aggregator:
			return true
		case *bgp.PathAttributeAs4Path:
			return ignoreAs4Path
		}
		return false
	})
}

// packer builds the UPDATE messages for the paths of one family.
type packer struct {
	eof    bool
	family bgp.Family
	total  uint32
	// useRemoteID reports the identifier the path was received with
	// instead of the one this speaker assigned. See
	// CreateUpdateMsgFromAdjRIBInPaths.
	useRemoteID bool
	paths       []*Path
	withdrawals []*Path
}

// pathID is the path identifier to put in front of the NLRI of path.
func (p *packer) pathID(path *Path) uint32 {
	if p.useRemoteID {
		return path.remoteID
	}
	return path.localID
}

// cage is a group of paths that share the attributes and the next hops, so
// that their NLRIs can go in the same UPDATE.
type cage struct {
	attrsBytes []byte
	nexthops   Nexthops
	paths      []*Path
}

func newCage(b []byte, nexthops Nexthops, path *Path) *cage {
	return &cage{
		attrsBytes: b,
		nexthops:   nexthops,
		paths:      []*Path{path},
	}
}

func (p *packer) add(path *Path) {
	p.total++

	if path.IsEOR() {
		p.eof = true
		return
	}

	if path.IsWithdraw {
		p.withdrawals = append(p.withdrawals, path)
		return
	}

	p.paths = append(p.paths, path)
}

// useNLRIField reports whether NLRIs with nexthops go in the NLRI field of
// the UPDATE with a NEXT_HOP attribute. Only IPv4 unicast with an IPv4 next
// hop does; anything else goes in MP_REACH_NLRI.
func (p *packer) useNLRIField(nexthops Nexthops) bool {
	return p.family == bgp.RF_IPv4_UC && nexthops.global.Is4()
}

func (p *packer) pack(options ...*bgp.MarshallingOption) []*bgp.BGPMessage {
	addpathNLRILen := 0
	if bgp.IsAddPathEnabled(false, p.family, options) {
		addpathNLRILen = 4
	}

	// split calls cb with as many NLRIs of paths as fit in an UPDATE
	// whose other parts take baseLen bytes. An NLRI that does not fit
	// even alone goes in an UPDATE of its own, which fails to serialize
	// and is logged when it is sent.
	split := func(baseLen int, paths []*Path, cb func([]bgp.PathNLRI)) {
		budget := maxUpdateMessageLength(options) - baseLen
		for len(paths) > 0 {
			used := 0
			n := 0
			for n < len(paths) {
				nlriLen := paths[n].GetNlri().Len(options...) + addpathNLRILen
				if n > 0 && used+nlriLen > budget {
					break
				}
				used += nlriLen
				n++
			}
			nlris := make([]bgp.PathNLRI, 0, n)
			for _, path := range paths[:n] {
				nlris = append(nlris, bgp.PathNLRI{NLRI: path.GetNlri(), ID: p.pathID(path)})
			}
			cb(nlris)
			paths = paths[n:]
		}
	}

	msgs := make([]*bgp.BGPMessage, 0, p.total)

	// The BGP header (19 bytes), Withdrawn Routes Length (2 bytes) and
	// Total Path Attribute Length (2 bytes), which every UPDATE has.
	const updateBaseLen = 19 + 2 + 2

	if p.family == bgp.RF_IPv4_UC {
		split(updateBaseLen, p.withdrawals, func(nlris []bgp.PathNLRI) {
			msgs = append(msgs, bgp.NewBGPUpdateMessage(nlris, nil, nil))
		})
	} else {
		emptyUnreach, _ := bgp.NewPathAttributeMpUnreachNLRI(p.family, nil)
		baseUnreachLen := updateBaseLen + emptyUnreach.Len() + 1 // +1 for extended-length attr header
		split(baseUnreachLen, p.withdrawals, func(nlris []bgp.PathNLRI) {
			unreach, _ := bgp.NewPathAttributeMpUnreachNLRI(p.family, nlris)
			msgs = append(msgs, bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{unreach}, nil))
		})
	}

	// serializedLen is the number of bytes a puts in an UPDATE. Len() is
	// not used: it comes from the Length field, which is stale after code
	// changes the value of an attribute in place, for example AS_PATH
	// after PrependAsn.
	serializedLen := func(a bgp.PathAttributeInterface) int {
		b, _ := a.Serialize()
		return len(b)
	}

	// announce packs paths that share the attributes and the next hops.
	// attrs and nexthops are those of paths[0], and attrsLen is the number
	// of bytes attrs take serialized. attrsLen is not used when there is
	// only one path, because one path always goes in one UPDATE.
	announce := func(paths []*Path, attrs []bgp.PathAttributeInterface, attrsLen int, nexthops Nexthops) {
		if p.useNLRIField(nexthops) {
			baseLen := updateBaseLen + attrsLen
			if nh, err := bgp.NewPathAttributeNextHop(nexthops.global); err == nil {
				attrs = insertPathAttr(attrs, nh)
				if len(paths) > 1 {
					baseLen += serializedLen(nh)
				}
			}
			split(baseLen, paths, func(nlris []bgp.PathNLRI) {
				msgs = append(msgs, bgp.NewBGPUpdateMessage(nil, attrs, nlris))
			})
			return
		}

		nhs := nexthops.list()
		baseLen := updateBaseLen + attrsLen
		if len(paths) > 1 {
			// The fixed part of MP_REACH_NLRI is its length with one
			// NLRI less that NLRI. +1 for the extended-length attribute
			// header that a longer MP_REACH_NLRI needs.
			sampleReach, _ := bgp.NewPathAttributeMpReachNLRI(p.family, []bgp.PathNLRI{{NLRI: paths[0].GetNlri()}}, nhs...)
			sampleNLRI, _ := paths[0].GetNlri().Serialize()
			baseLen += serializedLen(sampleReach) + 1 - len(sampleNLRI)
		}
		split(baseLen, paths, func(nlris []bgp.PathNLRI) {
			reach, _ := bgp.NewPathAttributeMpReachNLRI(p.family, nlris, nhs...)
			a := make([]bgp.PathAttributeInterface, 0, len(attrs)+1)
			a = append(a, attrs...)
			msgs = append(msgs, bgp.NewBGPUpdateMessage(nil, insertPathAttr(a, reach), nil))
		})
	}

	switch len(p.paths) {
	case 0:
	case 1:
		// A single path is a group by itself, and it goes in one UPDATE,
		// so its attributes need not be serialized.
		announce(p.paths, p.paths[0].GetPathAttrs(), 0, p.paths[0].nexthops())
	default:
		hashmap := make(map[uint64][]*cage)
		var attrsB []byte
		for _, path := range p.paths {
			attrs := path.GetPathAttrs()
			nexthops := path.nexthops()
			attrsB = attrsB[:0]
			for _, v := range attrs {
				b, _ := v.Serialize()
				attrsB = append(attrsB, b...)
			}

			// Paths with the same attributes and different next hops
			// must not share an UPDATE, so the next hop is part of the
			// key.
			global, linkLocal := nexthops.global.As16(), nexthops.linkLocal.As16()
			h := fnv1a.Init64
			h = fnv1a.AddBytes64(h, attrsB)
			h = fnv1a.AddBytes64(h, global[:])
			h = fnv1a.AddBytes64(h, linkLocal[:])

			added := false
			for _, c := range hashmap[h] {
				if c.nexthops == nexthops && bytes.Equal(c.attrsBytes, attrsB) {
					c.paths = append(c.paths, path)
					added = true
					break
				}
			}
			if !added {
				hashmap[h] = append(hashmap[h], newCage(bytes.Clone(attrsB), nexthops, path))
			}
		}

		for _, cages := range hashmap {
			for _, c := range cages {
				announce(c.paths, c.paths[0].GetPathAttrs(), len(c.attrsBytes), c.nexthops)
			}
		}
	}

	if p.eof {
		msgs = append(msgs, bgp.NewEndOfRib(p.family))
	}
	return msgs
}

func newPacker(f bgp.Family, useRemoteID bool) *packer {
	return &packer{
		family:      f,
		useRemoteID: useRemoteID,
	}
}

// CreateUpdateMsgFromAdjRIBInPaths builds UPDATE messages that report paths
// the way the peer sent them. The NLRI carries the path identifier received
// from the peer, not the one this speaker assigned for its own
// re-advertisement.
//
// RFC 7911 2 puts the identifier in the namespace of the speaker that
// advertised the path: "A BGP speaker that re-advertises a route MUST
// generate its own Path Identifier to be associated with the re-advertised
// route." An Adj-RIB-In report is the peer's advertisement, so it carries the
// peer's identifier. This speaker's own identifier means nothing there, and
// it is still 0 for a path that has not reached the global RIB.
func CreateUpdateMsgFromAdjRIBInPaths(pathList []*Path, options ...*bgp.MarshallingOption) []*bgp.BGPMessage {
	return createUpdateMsgFromPaths(pathList, true, options...)
}

func CreateUpdateMsgFromPaths(pathList []*Path, options ...*bgp.MarshallingOption) []*bgp.BGPMessage {
	return createUpdateMsgFromPaths(pathList, false, options...)
}

func createUpdateMsgFromPaths(pathList []*Path, useRemoteID bool, options ...*bgp.MarshallingOption) []*bgp.BGPMessage {
	msgs := make([]*bgp.BGPMessage, 0, len(pathList))

	key := func(path *Path) PathLocalKey {
		k := path.GetLocalKey()
		if useRemoteID {
			k.Id = path.remoteID
		}
		return k
	}

	// Since sendMessageloop coalesces outgoing BGP UPDATE messages and
	// the packers emit withdrawals before announcements, we should keep only the
	// last action for each NLRI/path-id within one packing pass.
	last := make(map[PathLocalKey]*Path, len(pathList))
	for _, path := range pathList {
		if path == nil || path.IsEOR() {
			continue
		}
		last[key(path)] = path
	}

	m := make(map[bgp.Family]*packer)
	add := func(path *Path) {
		f := path.GetFamily()
		if _, y := m[f]; !y {
			m[f] = newPacker(f, useRemoteID)
		}
		m[f].add(path)
	}

	for _, path := range pathList {
		if path == nil {
			continue
		}
		if path.IsEOR() {
			add(path)
			continue
		}
		if last[key(path)] != path {
			continue
		}
		add(path)
	}

	for _, p := range m {
		msgs = append(msgs, p.pack(options...)...)
	}
	return msgs
}
