// Copyright (C) 2016-2019 Nippon Telegraph and Telephone Corporation.
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
	"net"
	"sort"

	"github.com/k-sone/critbitgo"
	"github.com/osrg/gobgp/v3/internal/pkg/config"
	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

type ROA struct {
	Family  int
	Network *net.IPNet
	MaxLen  uint8
	AS      uint32
	Src     string
}

func NewROA(family int, prefixByte []byte, prefixLen uint8, maxLen uint8, as uint32, src string) *ROA {
	p := make([]byte, len(prefixByte))
	bits := net.IPv4len * 8
	if family == bgp.AFI_IP6 {
		bits = net.IPv6len * 8
	}
	copy(p, prefixByte)
	return &ROA{
		Family: family,
		Network: &net.IPNet{
			IP:   p,
			Mask: net.CIDRMask(int(prefixLen), bits),
		},
		MaxLen: maxLen,
		AS:     as,
		Src:    src,
	}
}

func (r *ROA) Equal(roa *ROA) bool {
	if r.MaxLen == roa.MaxLen && r.Src == roa.Src && r.AS == roa.AS {
		return true
	}
	return false
}

type roaBucket struct {
	network *net.IPNet
	entries []*ROA
}

func (r *roaBucket) GetEntries() []*ROA {
	return r.entries
}

type ROATable struct {
	trees  map[bgp.RouteFamily]*critbitgo.Net
	logger log.Logger
}

func NewROATable(logger log.Logger) *ROATable {
	m := make(map[bgp.RouteFamily]*critbitgo.Net)
	m[bgp.RF_IPv4_UC] = critbitgo.NewNet()
	m[bgp.RF_IPv6_UC] = critbitgo.NewNet()
	return &ROATable{
		trees:  m,
		logger: logger,
	}
}

func (rt *ROATable) roa2tree(roa *ROA) *critbitgo.Net {
	tree := rt.trees[bgp.RF_IPv4_UC]
	if roa.Family == bgp.AFI_IP6 {
		tree = rt.trees[bgp.RF_IPv6_UC]
	}
	return tree
}

func (rt *ROATable) getBucket(roa *ROA) *roaBucket {
	tree := rt.roa2tree(roa)
	b, ok, _ := tree.Get(roa.Network)
	if !ok {
		b := &roaBucket{
			network: roa.Network,
			entries: make([]*ROA, 0),
		}
		tree.Add(roa.Network, b)
		return b
	}
	return b.(*roaBucket)
}

func (rt *ROATable) Add(roa *ROA) {
	b := rt.getBucket(roa)
	for _, r := range b.entries {
		if r.Equal(roa) {
			// we already have the same one
			return
		}
	}
	b.entries = append(b.entries, roa)
	sort.Slice(b.entries, func(i, j int) bool {
		r1 := b.entries[i]
		r2 := b.entries[j]

		if r1.MaxLen < r2.MaxLen {
			return true
		} else if r1.MaxLen > r2.MaxLen {
			return false
		}

		if r1.AS < r2.AS {
			return true
		}
		return false
	})
}

func (rt *ROATable) Delete(roa *ROA) {
	tree := rt.roa2tree(roa)
	if b, ok, _ := tree.Get(roa.Network); ok {
		bucket := b.(*roaBucket)
		for i, r := range bucket.entries {
			if r.Equal(roa) {
				bucket.entries = append(bucket.entries[:i], bucket.entries[i+1:]...)
				return
			}
		}
	}
	rt.logger.Info("Can't withdraw a ROA",
		log.Fields{
			"Topic":      "rpki",
			"Network":    roa.Network.String(),
			"AS":         roa.AS,
			"Max Length": roa.MaxLen})
}

func (rt *ROATable) DeleteAll(network string) {
	for _, tree := range rt.trees {
		deleteNetworks := make([]*net.IPNet, 0, tree.Size())
		tree.Walk(nil, func(n *net.IPNet, v interface{}) bool {
			b, _ := v.(*roaBucket)
			newEntries := make([]*ROA, 0, len(b.entries))
			for _, r := range b.entries {
				if r.Src != network {
					newEntries = append(newEntries, r)
				}
			}
			if len(newEntries) > 0 {
				b.entries = newEntries
			} else {
				deleteNetworks = append(deleteNetworks, n)
			}
			return true
		})
		for _, key := range deleteNetworks {
			tree.Delete(key)
		}
	}
}

func (rt *ROATable) Validate(path *Path) *Validation {
	if path.IsWithdraw || path.IsEOR() {
		// RPKI isn't enabled or invalid path
		return nil
	}
	tree, ok := rt.trees[path.GetRouteFamily()]
	if !ok {
		return nil
	}

	ownAs := path.OriginInfo().source.LocalAS
	asPath := path.GetAsPath()
	var as uint32

	validation := &Validation{
		Status:          config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND,
		Reason:          RPKI_VALIDATION_REASON_TYPE_NONE,
		Matched:         make([]*ROA, 0),
		UnmatchedLength: make([]*ROA, 0),
		UnmatchedAs:     make([]*ROA, 0),
	}

	if asPath == nil || len(asPath.Value) == 0 {
		as = ownAs
	} else {
		param := asPath.Value[len(asPath.Value)-1]
		switch param.GetType() {
		case bgp.BGP_ASPATH_ATTR_TYPE_SEQ:
			asList := param.GetAS()
			if len(asList) == 0 {
				as = ownAs
			} else {
				as = asList[len(asList)-1]
			}
		case bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SET, bgp.BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
			as = ownAs
		default:
			return validation
		}
	}

	r := nlriToIPNet(path.GetNlri())
	prefixLen, _ := r.Mask.Size()
	var bucket *roaBucket
	tree.WalkMatch(r, func(r *net.IPNet, v interface{}) bool {
		bucket, _ = v.(*roaBucket)
		for _, r := range bucket.entries {
			if prefixLen <= int(r.MaxLen) {
				if r.AS != 0 && r.AS == as {
					validation.Matched = append(validation.Matched, r)
				} else {
					validation.UnmatchedAs = append(validation.UnmatchedAs, r)
				}
			} else {
				validation.UnmatchedLength = append(validation.UnmatchedLength, r)
			}
		}
		return true
	})

	if len(validation.Matched) != 0 {
		validation.Status = config.RPKI_VALIDATION_RESULT_TYPE_VALID
		validation.Reason = RPKI_VALIDATION_REASON_TYPE_NONE
	} else if len(validation.UnmatchedAs) != 0 {
		validation.Status = config.RPKI_VALIDATION_RESULT_TYPE_INVALID
		validation.Reason = RPKI_VALIDATION_REASON_TYPE_AS
	} else if len(validation.UnmatchedLength) != 0 {
		validation.Status = config.RPKI_VALIDATION_RESULT_TYPE_INVALID
		validation.Reason = RPKI_VALIDATION_REASON_TYPE_LENGTH
	} else {
		validation.Status = config.RPKI_VALIDATION_RESULT_TYPE_NOT_FOUND
		validation.Reason = RPKI_VALIDATION_REASON_TYPE_NONE
	}

	return validation
}

func (rt *ROATable) Info(family bgp.RouteFamily) (map[string]uint32, map[string]uint32) {
	records := make(map[string]uint32)
	prefixes := make(map[string]uint32)

	if tree, ok := rt.trees[family]; ok {
		tree.Walk(nil, func(_ *net.IPNet, v interface{}) bool {
			b, _ := v.(*roaBucket)
			tmpRecords := make(map[string]uint32)
			for _, roa := range b.entries {
				tmpRecords[roa.Src]++
			}

			for src, r := range tmpRecords {
				if r > 0 {
					records[src] += r
					prefixes[src]++
				}
			}
			return true
		})
	}
	return records, prefixes
}

func (rt *ROATable) List(family bgp.RouteFamily) ([]*ROA, error) {
	var rfList []bgp.RouteFamily
	switch family {
	case bgp.RF_IPv4_UC:
		rfList = []bgp.RouteFamily{bgp.RF_IPv4_UC}
	case bgp.RF_IPv6_UC:
		rfList = []bgp.RouteFamily{bgp.RF_IPv6_UC}
	default:
		rfList = []bgp.RouteFamily{bgp.RF_IPv4_UC, bgp.RF_IPv6_UC}
	}
	l := make([]*ROA, 0)
	for _, rf := range rfList {
		if tree, ok := rt.trees[rf]; ok {
			tree.Walk(nil, func(_ *net.IPNet, v interface{}) bool {
				b, _ := v.(*roaBucket)
				l = append(l, b.entries...)
				return true
			})
		}
	}
	return l, nil
}
