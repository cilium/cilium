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
	"reflect"

	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

func UpdatePathAttrs2ByteAs(msg *bgp.BGPUpdate) error {
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
		return nil
	}

	as4Params := make([]*bgp.As4PathParam, 0, len(asAttr.Value))
	as2Params := make([]bgp.AsPathParamInterface, 0, len(asAttr.Value))
	mkAs4 := false
	for _, param := range asAttr.Value {
		segType := param.GetType()
		asList := param.GetAS()
		as2Path := make([]uint16, 0, len(asList))
		for _, as := range asList {
			if as > (1<<16)-1 {
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
	return nil
}

func UpdatePathAttrs4ByteAs(logger log.Logger, msg *bgp.BGPUpdate) error {
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
	}

	if asAttr == nil || as4Attr == nil {
		return nil
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
					log.Fields{
						"Topic": "Table"})
				continue
			}
			as4Len += p.ASLen()
			as4Params = append(as4Params, p)
		}
	}

	if asLen+asConfedLen < as4Len {
		logger.Warn("AS4_PATH is longer than AS_PATH. ignore AS4_PATH",
			log.Fields{
				"Topic": "Table"})
		return nil
	}

	keepNum := asLen + asConfedLen - as4Len

	newParams := make([]bgp.AsPathParamInterface, 0, len(asAttr.Value))
	for _, param := range asParams {
		if keepNum-param.ASLen() >= 0 {
			newParams = append(newParams, param)
			keepNum -= param.ASLen()
		} else {
			// only SEQ param reaches here
			newParams = append(newParams, bgp.NewAs4PathParam(param.GetType(), param.GetAS()[:keepNum]))
			keepNum = 0
		}

		if keepNum <= 0 {
			break
		}
	}

	for _, param := range as4Params {
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
	return nil
}

func UpdatePathAggregator2ByteAs(msg *bgp.BGPUpdate) {
	as := uint32(0)
	var addr string
	for i, attr := range msg.PathAttributes {
		switch agg := attr.(type) {
		case *bgp.PathAttributeAggregator:
			addr = agg.Value.Address.String()
			if agg.Value.AS > (1<<16)-1 {
				as = agg.Value.AS
				msg.PathAttributes[i] = bgp.NewPathAttributeAggregator(uint16(bgp.AS_TRANS), addr)
			} else {
				msg.PathAttributes[i] = bgp.NewPathAttributeAggregator(uint16(agg.Value.AS), addr)
			}
		}
	}
	if as != 0 {
		msg.PathAttributes = append(msg.PathAttributes, bgp.NewPathAttributeAs4Aggregator(as, addr))
	}
}

func UpdatePathAggregator4ByteAs(msg *bgp.BGPUpdate) error {
	var aggAttr *bgp.PathAttributeAggregator
	var agg4Attr *bgp.PathAttributeAs4Aggregator
	agg4AttrPos := 0
	for i, attr := range msg.PathAttributes {
		switch agg := attr.(type) {
		case *bgp.PathAttributeAggregator:
			attr := agg
			if attr.Value.Askind == reflect.Uint16 {
				aggAttr = attr
				aggAttr.Value.Askind = reflect.Uint32
			}
		case *bgp.PathAttributeAs4Aggregator:
			agg4Attr = agg
			agg4AttrPos = i
		}
	}
	if aggAttr == nil && agg4Attr == nil {
		return nil
	}

	if aggAttr == nil && agg4Attr != nil {
		return bgp.NewMessageError(bgp.BGP_ERROR_UPDATE_MESSAGE_ERROR, bgp.BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "AS4 AGGREGATOR attribute exists, but AGGREGATOR doesn't")
	}

	if agg4Attr != nil {
		msg.PathAttributes = append(msg.PathAttributes[:agg4AttrPos], msg.PathAttributes[agg4AttrPos+1:]...)
		aggAttr.Value.AS = agg4Attr.Value.AS
	}
	return nil
}

type cage struct {
	attrsBytes []byte
	paths      []*Path
}

func newCage(b []byte, path *Path) *cage {
	return &cage{
		attrsBytes: b,
		paths:      []*Path{path},
	}
}

type packerInterface interface {
	add(*Path)
	pack(options ...*bgp.MarshallingOption) []*bgp.BGPMessage
}

type packer struct {
	eof    bool
	family bgp.RouteFamily
	total  uint32
}

type packerMP struct {
	packer
	paths       []*Path
	withdrawals []*Path
}

func (p *packerMP) add(path *Path) {
	p.packer.total++

	if path.IsEOR() {
		p.packer.eof = true
		return
	}

	if path.IsWithdraw {
		p.withdrawals = append(p.withdrawals, path)
		return
	}

	p.paths = append(p.paths, path)
}

func createMPReachMessage(path *Path) *bgp.BGPMessage {
	oattrs := path.GetPathAttrs()
	attrs := make([]bgp.PathAttributeInterface, 0, len(oattrs))
	for _, a := range oattrs {
		if a.GetType() == bgp.BGP_ATTR_TYPE_MP_REACH_NLRI {
			attrs = append(attrs, bgp.NewPathAttributeMpReachNLRI(path.GetNexthop().String(), []bgp.AddrPrefixInterface{path.GetNlri()}))
		} else {
			attrs = append(attrs, a)
		}
	}
	return bgp.NewBGPUpdateMessage(nil, attrs, nil)
}

func (p *packerMP) pack(options ...*bgp.MarshallingOption) []*bgp.BGPMessage {
	msgs := make([]*bgp.BGPMessage, 0, p.packer.total)

	for _, path := range p.withdrawals {
		nlris := []bgp.AddrPrefixInterface{path.GetNlri()}
		msgs = append(msgs, bgp.NewBGPUpdateMessage(nil, []bgp.PathAttributeInterface{bgp.NewPathAttributeMpUnreachNLRI(nlris)}, nil))
	}

	for _, path := range p.paths {
		msgs = append(msgs, createMPReachMessage(path))
	}

	if p.eof {
		msgs = append(msgs, bgp.NewEndOfRib(p.family))
	}
	return msgs
}

func newPackerMP(f bgp.RouteFamily) *packerMP {
	return &packerMP{
		packer: packer{
			family: f,
		},
		withdrawals: make([]*Path, 0),
		paths:       make([]*Path, 0),
	}
}

type packerV4 struct {
	packer
	hashmap     map[uint32][]*cage
	mpPaths     []*Path
	withdrawals []*Path
}

func (p *packerV4) add(path *Path) {
	p.packer.total++

	if path.IsEOR() {
		p.packer.eof = true
		return
	}

	if path.IsWithdraw {
		p.withdrawals = append(p.withdrawals, path)
		return
	}

	if path.GetNexthop().To4() == nil {
		// RFC 5549
		p.mpPaths = append(p.mpPaths, path)
		return
	}

	key := path.GetHash()
	attrsB := bytes.NewBuffer(make([]byte, 0))
	for _, v := range path.GetPathAttrs() {
		b, _ := v.Serialize()
		attrsB.Write(b)
	}

	if cages, y := p.hashmap[key]; y {
		added := false
		for _, c := range cages {
			if bytes.Equal(c.attrsBytes, attrsB.Bytes()) {
				c.paths = append(c.paths, path)
				added = true
				break
			}
		}
		if !added {
			p.hashmap[key] = append(p.hashmap[key], newCage(attrsB.Bytes(), path))
		}
	} else {
		p.hashmap[key] = []*cage{newCage(attrsB.Bytes(), path)}
	}
}

func (p *packerV4) pack(options ...*bgp.MarshallingOption) []*bgp.BGPMessage {
	split := func(max int, paths []*Path) ([]*bgp.IPAddrPrefix, []*Path) {
		nlris := make([]*bgp.IPAddrPrefix, 0, max)
		i := 0
		if max > len(paths) {
			max = len(paths)
		}
		for ; i < max; i++ {
			nlris = append(nlris, paths[i].GetNlri().(*bgp.IPAddrPrefix))
		}
		return nlris, paths[i:]
	}
	addpathNLRILen := 0
	if bgp.IsAddPathEnabled(false, p.packer.family, options) {
		addpathNLRILen = 4
	}
	// Header + Update (WithdrawnRoutesLen +
	// TotalPathAttributeLen + attributes + maxlen of NLRI).
	// the max size of NLRI is 5bytes (plus 4bytes with addpath enabled)
	maxNLRIs := func(attrsLen int) int {
		return (bgp.BGP_MAX_MESSAGE_LENGTH - (19 + 2 + 2 + attrsLen)) / (5 + addpathNLRILen)
	}

	loop := func(attrsLen int, paths []*Path, cb func([]*bgp.IPAddrPrefix)) {
		max := maxNLRIs(attrsLen)
		var nlris []*bgp.IPAddrPrefix
		for {
			nlris, paths = split(max, paths)
			if len(nlris) == 0 {
				break
			}
			cb(nlris)
		}
	}

	msgs := make([]*bgp.BGPMessage, 0, p.packer.total)

	loop(0, p.withdrawals, func(nlris []*bgp.IPAddrPrefix) {
		msgs = append(msgs, bgp.NewBGPUpdateMessage(nlris, nil, nil))
	})

	for _, cages := range p.hashmap {
		for _, c := range cages {
			paths := c.paths

			attrs := paths[0].GetPathAttrs()
			// we can apply a fix here when gobgp receives from MP peer
			// and propagtes to non-MP peer
			// we should make sure that next-hop exists in pathattrs
			// while we build the update message
			// we do not want to modify the `path` though
			if paths[0].getPathAttr(bgp.BGP_ATTR_TYPE_NEXT_HOP) == nil {
				attrs = append(attrs, bgp.NewPathAttributeNextHop(paths[0].GetNexthop().String()))
			}
			// if we have ever reach here
			// there is no point keeping MP_REACH_NLRI in the announcement
			attrs_without_mp := make([]bgp.PathAttributeInterface, 0, len(attrs))
			for _, attr := range attrs {
				if attr.GetType() != bgp.BGP_ATTR_TYPE_MP_REACH_NLRI {
					attrs_without_mp = append(attrs_without_mp, attr)
				}
			}
			attrsLen := 0
			for _, a := range attrs_without_mp {
				attrsLen += a.Len()
			}

			loop(attrsLen, paths, func(nlris []*bgp.IPAddrPrefix) {
				msgs = append(msgs, bgp.NewBGPUpdateMessage(nil, attrs_without_mp, nlris))
			})
		}
	}

	for _, path := range p.mpPaths {
		msgs = append(msgs, createMPReachMessage(path))
	}

	if p.eof {
		msgs = append(msgs, bgp.NewEndOfRib(p.family))
	}
	return msgs
}

func newPackerV4(f bgp.RouteFamily) *packerV4 {
	return &packerV4{
		packer: packer{
			family: f,
		},
		hashmap:     make(map[uint32][]*cage),
		withdrawals: make([]*Path, 0),
		mpPaths:     make([]*Path, 0),
	}
}

func newPacker(f bgp.RouteFamily) packerInterface {
	switch f {
	case bgp.RF_IPv4_UC:
		return newPackerV4(bgp.RF_IPv4_UC)
	default:
		return newPackerMP(f)
	}
}

func CreateUpdateMsgFromPaths(pathList []*Path, options ...*bgp.MarshallingOption) []*bgp.BGPMessage {
	msgs := make([]*bgp.BGPMessage, 0, len(pathList))

	m := make(map[bgp.RouteFamily]packerInterface)
	for _, path := range pathList {
		f := path.GetRouteFamily()
		if _, y := m[f]; !y {
			m[f] = newPacker(f)
		}
		m[f].add(path)
	}

	for _, p := range m {
		msgs = append(msgs, p.pack(options...)...)
	}
	return msgs
}
