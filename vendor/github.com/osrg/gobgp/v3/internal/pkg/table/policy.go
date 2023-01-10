// Copyright (C) 2014-2016 Nippon Telegraph and Telephone Corporation.
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
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/k-sone/critbitgo"
	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/internal/pkg/config"
	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

type PolicyOptions struct {
	Info       *PeerInfo
	OldNextHop net.IP
	Validate   func(*Path) *Validation
}

type DefinedType int

const (
	DEFINED_TYPE_PREFIX DefinedType = iota
	DEFINED_TYPE_NEIGHBOR
	DEFINED_TYPE_TAG
	DEFINED_TYPE_AS_PATH
	DEFINED_TYPE_COMMUNITY
	DEFINED_TYPE_EXT_COMMUNITY
	DEFINED_TYPE_LARGE_COMMUNITY
	DEFINED_TYPE_NEXT_HOP
)

type RouteType int

const (
	ROUTE_TYPE_NONE RouteType = iota
	ROUTE_TYPE_ACCEPT
	ROUTE_TYPE_REJECT
)

func (t RouteType) String() string {
	switch t {
	case ROUTE_TYPE_NONE:
		return "continue"
	case ROUTE_TYPE_ACCEPT:
		return "accept"
	case ROUTE_TYPE_REJECT:
		return "reject"
	}
	return fmt.Sprintf("unknown(%d)", t)
}

type PolicyDirection int

const (
	POLICY_DIRECTION_NONE PolicyDirection = iota
	POLICY_DIRECTION_IMPORT
	POLICY_DIRECTION_EXPORT
)

func (d PolicyDirection) String() string {
	switch d {
	case POLICY_DIRECTION_IMPORT:
		return "import"
	case POLICY_DIRECTION_EXPORT:
		return "export"
	}
	return fmt.Sprintf("unknown(%d)", d)
}

type MatchOption int

const (
	MATCH_OPTION_ANY MatchOption = iota
	MATCH_OPTION_ALL
	MATCH_OPTION_INVERT
)

func (o MatchOption) String() string {
	switch o {
	case MATCH_OPTION_ANY:
		return "any"
	case MATCH_OPTION_ALL:
		return "all"
	case MATCH_OPTION_INVERT:
		return "invert"
	default:
		return fmt.Sprintf("MatchOption(%d)", o)
	}
}

func (o MatchOption) ConvertToMatchSetOptionsRestrictedType() config.MatchSetOptionsRestrictedType {
	switch o {
	case MATCH_OPTION_ANY:
		return config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY
	case MATCH_OPTION_INVERT:
		return config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT
	}
	return "unknown"
}

type MedActionType int

const (
	MED_ACTION_MOD MedActionType = iota
	MED_ACTION_REPLACE
)

var CommunityOptionNameMap = map[config.BgpSetCommunityOptionType]string{
	config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD:     "add",
	config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE:  "remove",
	config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE: "replace",
}

var CommunityOptionValueMap = map[string]config.BgpSetCommunityOptionType{
	CommunityOptionNameMap[config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD]:     config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD,
	CommunityOptionNameMap[config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE]:  config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE,
	CommunityOptionNameMap[config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE]: config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE,
}

type ConditionType int

const (
	CONDITION_PREFIX ConditionType = iota
	CONDITION_NEIGHBOR
	CONDITION_AS_PATH
	CONDITION_COMMUNITY
	CONDITION_EXT_COMMUNITY
	CONDITION_AS_PATH_LENGTH
	CONDITION_RPKI
	CONDITION_ROUTE_TYPE
	CONDITION_LARGE_COMMUNITY
	CONDITION_NEXT_HOP
	CONDITION_AFI_SAFI_IN
)

type ActionType int

const (
	ACTION_ROUTING ActionType = iota
	ACTION_COMMUNITY
	ACTION_EXT_COMMUNITY
	ACTION_MED
	ACTION_AS_PATH_PREPEND
	ACTION_NEXTHOP
	ACTION_LOCAL_PREF
	ACTION_LARGE_COMMUNITY
)

func NewMatchOption(c interface{}) (MatchOption, error) {
	switch t := c.(type) {
	case config.MatchSetOptionsType:
		t = t.DefaultAsNeeded()
		switch t {
		case config.MATCH_SET_OPTIONS_TYPE_ANY:
			return MATCH_OPTION_ANY, nil
		case config.MATCH_SET_OPTIONS_TYPE_ALL:
			return MATCH_OPTION_ALL, nil
		case config.MATCH_SET_OPTIONS_TYPE_INVERT:
			return MATCH_OPTION_INVERT, nil
		}
	case config.MatchSetOptionsRestrictedType:
		t = t.DefaultAsNeeded()
		switch t {
		case config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_ANY:
			return MATCH_OPTION_ANY, nil
		case config.MATCH_SET_OPTIONS_RESTRICTED_TYPE_INVERT:
			return MATCH_OPTION_INVERT, nil
		}
	}
	return MATCH_OPTION_ANY, fmt.Errorf("invalid argument to create match option: %v", c)
}

type AttributeComparison int

const (
	// "== comparison"
	ATTRIBUTE_EQ AttributeComparison = iota
	// ">= comparison"
	ATTRIBUTE_GE
	// "<= comparison"
	ATTRIBUTE_LE
)

func (c AttributeComparison) String() string {
	switch c {
	case ATTRIBUTE_EQ:
		return "="
	case ATTRIBUTE_GE:
		return ">="
	case ATTRIBUTE_LE:
		return "<="
	}
	return "?"
}

const (
	ASPATH_REGEXP_MAGIC = "(^|[,{}() ]|$)"
)

type DefinedSet interface {
	Type() DefinedType
	Name() string
	Append(DefinedSet) error
	Remove(DefinedSet) error
	Replace(DefinedSet) error
	String() string
	List() []string
}

type DefinedSetMap map[DefinedType]map[string]DefinedSet

type DefinedSetList []DefinedSet

func (l DefinedSetList) Len() int {
	return len(l)
}

func (l DefinedSetList) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

func (l DefinedSetList) Less(i, j int) bool {
	if l[i].Type() != l[j].Type() {
		return l[i].Type() < l[j].Type()
	}
	return l[i].Name() < l[j].Name()
}

type Prefix struct {
	Prefix             *net.IPNet
	AddressFamily      bgp.RouteFamily
	MasklengthRangeMax uint8
	MasklengthRangeMin uint8
}

func (p *Prefix) Match(path *Path) bool {
	rf := path.GetRouteFamily()
	if rf != p.AddressFamily {
		return false
	}

	var pAddr net.IP
	var pMasklen uint8
	switch rf {
	case bgp.RF_IPv4_UC:
		pAddr = path.GetNlri().(*bgp.IPAddrPrefix).Prefix
		pMasklen = path.GetNlri().(*bgp.IPAddrPrefix).Length
	case bgp.RF_IPv6_UC:
		pAddr = path.GetNlri().(*bgp.IPv6AddrPrefix).Prefix
		pMasklen = path.GetNlri().(*bgp.IPv6AddrPrefix).Length
	default:
		return false
	}

	return (p.MasklengthRangeMin <= pMasklen && pMasklen <= p.MasklengthRangeMax) && p.Prefix.Contains(pAddr)
}

func (lhs *Prefix) Equal(rhs *Prefix) bool {
	if lhs == rhs {
		return true
	}
	if rhs == nil {
		return false
	}
	return lhs.Prefix.String() == rhs.Prefix.String() && lhs.MasklengthRangeMin == rhs.MasklengthRangeMin && lhs.MasklengthRangeMax == rhs.MasklengthRangeMax
}

func (p *Prefix) PrefixString() string {
	isZeros := func(p net.IP) bool {
		for i := 0; i < len(p); i++ {
			if p[i] != 0 {
				return false
			}
		}
		return true
	}

	ip := p.Prefix.IP
	if p.AddressFamily == bgp.RF_IPv6_UC && isZeros(ip[0:10]) && ip[10] == 0xff && ip[11] == 0xff {
		m, _ := p.Prefix.Mask.Size()
		return fmt.Sprintf("::FFFF:%s/%d", ip.To16(), m)
	}
	return p.Prefix.String()
}

var _regexpPrefixRange = regexp.MustCompile(`(\d+)\.\.(\d+)`)

func NewPrefix(c config.Prefix) (*Prefix, error) {
	_, prefix, err := net.ParseCIDR(c.IpPrefix)
	if err != nil {
		return nil, err
	}

	rf := bgp.RF_IPv4_UC
	if strings.Contains(c.IpPrefix, ":") {
		rf = bgp.RF_IPv6_UC
	}
	p := &Prefix{
		Prefix:        prefix,
		AddressFamily: rf,
	}
	maskRange := c.MasklengthRange

	if maskRange == "" {
		l, _ := prefix.Mask.Size()
		maskLength := uint8(l)
		p.MasklengthRangeMax = maskLength
		p.MasklengthRangeMin = maskLength
		return p, nil
	}

	elems := _regexpPrefixRange.FindStringSubmatch(maskRange)
	if len(elems) != 3 {
		return nil, fmt.Errorf("mask length range format is invalid")
	}

	// we've already checked the range is sane by regexp
	min, _ := strconv.ParseUint(elems[1], 10, 8)
	max, _ := strconv.ParseUint(elems[2], 10, 8)
	p.MasklengthRangeMin = uint8(min)
	p.MasklengthRangeMax = uint8(max)
	return p, nil
}

type PrefixSet struct {
	name   string
	tree   *critbitgo.Net
	family bgp.RouteFamily
}

func (s *PrefixSet) Name() string {
	return s.name
}

func (s *PrefixSet) Type() DefinedType {
	return DEFINED_TYPE_PREFIX
}

func (lhs *PrefixSet) Append(arg DefinedSet) error {
	rhs, ok := arg.(*PrefixSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}

	if rhs.tree.Size() == 0 {
		// if try to append an empty set, then return directly
		return nil
	} else if lhs.tree.Size() != 0 && rhs.family != lhs.family {
		return fmt.Errorf("can't append different family")
	}
	rhs.tree.Walk(nil, func(r *net.IPNet, v interface{}) bool {
		w, ok, _ := lhs.tree.Get(r)
		if ok {
			rp := v.([]*Prefix)
			lp := w.([]*Prefix)
			lhs.tree.Add(r, append(lp, rp...))
		} else {
			lhs.tree.Add(r, v)
		}
		return true
	})
	lhs.family = rhs.family
	return nil
}

func (lhs *PrefixSet) Remove(arg DefinedSet) error {
	rhs, ok := arg.(*PrefixSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	rhs.tree.Walk(nil, func(r *net.IPNet, v interface{}) bool {
		w, ok, _ := lhs.tree.Get(r)
		if !ok {
			return true
		}
		rp := v.([]*Prefix)
		lp := w.([]*Prefix)
		new := make([]*Prefix, 0, len(lp))
		for _, lp := range lp {
			delete := false
			for _, rp := range rp {
				if lp.Equal(rp) {
					delete = true
					break
				}
			}
			if !delete {
				new = append(new, lp)
			}
		}
		if len(new) == 0 {
			lhs.tree.Delete(r)
		} else {
			lhs.tree.Add(r, new)
		}
		return true
	})
	return nil
}

func (lhs *PrefixSet) Replace(arg DefinedSet) error {
	rhs, ok := arg.(*PrefixSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	lhs.tree = rhs.tree
	lhs.family = rhs.family
	return nil
}

func (s *PrefixSet) List() []string {
	var list []string
	s.tree.Walk(nil, func(_ *net.IPNet, v interface{}) bool {
		ps := v.([]*Prefix)
		for _, p := range ps {
			list = append(list, fmt.Sprintf("%s %d..%d", p.PrefixString(), p.MasklengthRangeMin, p.MasklengthRangeMax))
		}
		return true
	})
	return list
}

func (s *PrefixSet) ToConfig() *config.PrefixSet {
	list := make([]config.Prefix, 0, s.tree.Size())
	s.tree.Walk(nil, func(_ *net.IPNet, v interface{}) bool {
		ps := v.([]*Prefix)
		for _, p := range ps {
			list = append(list, config.Prefix{IpPrefix: p.PrefixString(), MasklengthRange: fmt.Sprintf("%d..%d", p.MasklengthRangeMin, p.MasklengthRangeMax)})
		}
		return true
	})
	return &config.PrefixSet{
		PrefixSetName: s.name,
		PrefixList:    list,
	}
}

func (s *PrefixSet) String() string {
	return strings.Join(s.List(), "\n")
}

func (s *PrefixSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.ToConfig())
}

func NewPrefixSetFromApiStruct(name string, prefixes []*Prefix) (*PrefixSet, error) {
	if name == "" {
		return nil, fmt.Errorf("empty prefix set name")
	}
	tree := critbitgo.NewNet()
	var family bgp.RouteFamily
	for i, x := range prefixes {
		if i == 0 {
			family = x.AddressFamily
		} else if family != x.AddressFamily {
			return nil, fmt.Errorf("multiple families")
		}
		d, ok, _ := tree.Get(x.Prefix)
		if ok {
			ps := d.([]*Prefix)
			tree.Add(x.Prefix, append(ps, x))
		} else {
			tree.Add(x.Prefix, []*Prefix{x})
		}
	}
	return &PrefixSet{
		name:   name,
		tree:   tree,
		family: family,
	}, nil
}

func NewPrefixSet(c config.PrefixSet) (*PrefixSet, error) {
	name := c.PrefixSetName
	if name == "" {
		if len(c.PrefixList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty prefix set name")
	}
	tree := critbitgo.NewNet()
	var family bgp.RouteFamily
	for i, x := range c.PrefixList {
		y, err := NewPrefix(x)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			family = y.AddressFamily
		} else if family != y.AddressFamily {
			return nil, fmt.Errorf("multiple families")
		}
		d, ok, _ := tree.Get(y.Prefix)
		if ok {
			ps := d.([]*Prefix)
			tree.Add(y.Prefix, append(ps, y))
		} else {
			tree.Add(y.Prefix, []*Prefix{y})
		}
	}
	return &PrefixSet{
		name:   name,
		tree:   tree,
		family: family,
	}, nil
}

type NextHopSet struct {
	list []net.IPNet
}

func (s *NextHopSet) Name() string {
	return "NextHopSet: NO NAME"
}

func (s *NextHopSet) Type() DefinedType {
	return DEFINED_TYPE_NEXT_HOP
}

func (lhs *NextHopSet) Append(arg DefinedSet) error {
	rhs, ok := arg.(*NextHopSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	lhs.list = append(lhs.list, rhs.list...)
	return nil
}

func (lhs *NextHopSet) Remove(arg DefinedSet) error {
	rhs, ok := arg.(*NextHopSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	ps := make([]net.IPNet, 0, len(lhs.list))
	for _, x := range lhs.list {
		found := false
		for _, y := range rhs.list {
			if x.String() == y.String() {
				found = true
				break
			}
		}
		if !found {
			ps = append(ps, x)
		}
	}
	lhs.list = ps
	return nil
}

func (lhs *NextHopSet) Replace(arg DefinedSet) error {
	rhs, ok := arg.(*NextHopSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	lhs.list = rhs.list
	return nil
}

func (s *NextHopSet) List() []string {
	list := make([]string, 0, len(s.list))
	for _, n := range s.list {
		list = append(list, n.String())
	}
	return list
}

func (s *NextHopSet) ToConfig() []string {
	return s.List()
}

func (s *NextHopSet) String() string {
	return "[ " + strings.Join(s.List(), ", ") + " ]"
}

func (s *NextHopSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.ToConfig())
}

func NewNextHopSetFromApiStruct(name string, list []net.IPNet) (*NextHopSet, error) {
	return &NextHopSet{
		list: list,
	}, nil
}

func NewNextHopSet(c []string) (*NextHopSet, error) {
	list := make([]net.IPNet, 0, len(c))
	for _, x := range c {
		_, cidr, err := net.ParseCIDR(x)
		if err != nil {
			addr := net.ParseIP(x)
			if addr == nil {
				return nil, fmt.Errorf("invalid address or prefix: %s", x)
			}
			mask := net.CIDRMask(32, 32)
			if addr.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			cidr = &net.IPNet{
				IP:   addr,
				Mask: mask,
			}
		}
		list = append(list, *cidr)
	}
	return &NextHopSet{
		list: list,
	}, nil
}

type NeighborSet struct {
	name string
	list []net.IPNet
}

func (s *NeighborSet) Name() string {
	return s.name
}

func (s *NeighborSet) Type() DefinedType {
	return DEFINED_TYPE_NEIGHBOR
}

func (lhs *NeighborSet) Append(arg DefinedSet) error {
	rhs, ok := arg.(*NeighborSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	lhs.list = append(lhs.list, rhs.list...)
	return nil
}

func (lhs *NeighborSet) Remove(arg DefinedSet) error {
	rhs, ok := arg.(*NeighborSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	ps := make([]net.IPNet, 0, len(lhs.list))
	for _, x := range lhs.list {
		found := false
		for _, y := range rhs.list {
			if x.String() == y.String() {
				found = true
				break
			}
		}
		if !found {
			ps = append(ps, x)
		}
	}
	lhs.list = ps
	return nil
}

func (lhs *NeighborSet) Replace(arg DefinedSet) error {
	rhs, ok := arg.(*NeighborSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	lhs.list = rhs.list
	return nil
}

func (s *NeighborSet) List() []string {
	list := make([]string, 0, len(s.list))
	for _, n := range s.list {
		list = append(list, n.String())
	}
	return list
}

func (s *NeighborSet) ToConfig() *config.NeighborSet {
	return &config.NeighborSet{
		NeighborSetName:  s.name,
		NeighborInfoList: s.List(),
	}
}

func (s *NeighborSet) String() string {
	return strings.Join(s.List(), "\n")
}

func (s *NeighborSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.ToConfig())
}

func NewNeighborSetFromApiStruct(name string, list []net.IPNet) (*NeighborSet, error) {
	return &NeighborSet{
		name: name,
		list: list,
	}, nil
}

func NewNeighborSet(c config.NeighborSet) (*NeighborSet, error) {
	name := c.NeighborSetName
	if name == "" {
		if len(c.NeighborInfoList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty neighbor set name")
	}
	list := make([]net.IPNet, 0, len(c.NeighborInfoList))
	for _, x := range c.NeighborInfoList {
		_, cidr, err := net.ParseCIDR(x)
		if err != nil {
			addr := net.ParseIP(x)
			if addr == nil {
				return nil, fmt.Errorf("invalid address or prefix: %s", x)
			}
			mask := net.CIDRMask(32, 32)
			if addr.To4() == nil {
				mask = net.CIDRMask(128, 128)
			}
			cidr = &net.IPNet{
				IP:   addr,
				Mask: mask,
			}
		}
		list = append(list, *cidr)
	}
	return &NeighborSet{
		name: name,
		list: list,
	}, nil
}

type singleAsPathMatchMode int

const (
	INCLUDE singleAsPathMatchMode = iota
	LEFT_MOST
	ORIGIN
	ONLY
)

type singleAsPathMatch struct {
	asn  uint32
	mode singleAsPathMatchMode
}

func (lhs *singleAsPathMatch) Equal(rhs *singleAsPathMatch) bool {
	return lhs.asn == rhs.asn && lhs.mode == rhs.mode
}

func (lhs *singleAsPathMatch) String() string {
	switch lhs.mode {
	case INCLUDE:
		return fmt.Sprintf("_%d_", lhs.asn)
	case LEFT_MOST:
		return fmt.Sprintf("^%d_", lhs.asn)
	case ORIGIN:
		return fmt.Sprintf("_%d$", lhs.asn)
	case ONLY:
		return fmt.Sprintf("^%d$", lhs.asn)
	}
	return ""
}

func (m *singleAsPathMatch) Match(aspath []uint32) bool {
	if len(aspath) == 0 {
		return false
	}
	switch m.mode {
	case INCLUDE:
		for _, asn := range aspath {
			if m.asn == asn {
				return true
			}
		}
	case LEFT_MOST:
		if m.asn == aspath[0] {
			return true
		}
	case ORIGIN:
		if m.asn == aspath[len(aspath)-1] {
			return true
		}
	case ONLY:
		if len(aspath) == 1 && m.asn == aspath[0] {
			return true
		}
	}
	return false
}

var (
	_regexpLeftMostRe = regexp.MustCompile(`^\^([0-9]+)_$`)
	_regexpOriginRe   = regexp.MustCompile(`^_([0-9]+)\$$`)
	_regexpIncludeRe  = regexp.MustCompile("^_([0-9]+)_$")
	_regexpOnlyRe     = regexp.MustCompile(`^\^([0-9]+)\$$`)
)

func NewSingleAsPathMatch(arg string) *singleAsPathMatch {
	switch {
	case _regexpLeftMostRe.MatchString(arg):
		asn, _ := strconv.ParseUint(_regexpLeftMostRe.FindStringSubmatch(arg)[1], 10, 32)
		return &singleAsPathMatch{
			asn:  uint32(asn),
			mode: LEFT_MOST,
		}
	case _regexpOriginRe.MatchString(arg):
		asn, _ := strconv.ParseUint(_regexpOriginRe.FindStringSubmatch(arg)[1], 10, 32)
		return &singleAsPathMatch{
			asn:  uint32(asn),
			mode: ORIGIN,
		}
	case _regexpIncludeRe.MatchString(arg):
		asn, _ := strconv.ParseUint(_regexpIncludeRe.FindStringSubmatch(arg)[1], 10, 32)
		return &singleAsPathMatch{
			asn:  uint32(asn),
			mode: INCLUDE,
		}
	case _regexpOnlyRe.MatchString(arg):
		asn, _ := strconv.ParseUint(_regexpOnlyRe.FindStringSubmatch(arg)[1], 10, 32)
		return &singleAsPathMatch{
			asn:  uint32(asn),
			mode: ONLY,
		}
	}
	return nil
}

type AsPathSet struct {
	typ        DefinedType
	name       string
	list       []*regexp.Regexp
	singleList []*singleAsPathMatch
}

func (s *AsPathSet) Name() string {
	return s.name
}

func (s *AsPathSet) Type() DefinedType {
	return s.typ
}

func (lhs *AsPathSet) Append(arg DefinedSet) error {
	if lhs.Type() != arg.Type() {
		return fmt.Errorf("can't append to different type of defined-set")
	}
	lhs.list = append(lhs.list, arg.(*AsPathSet).list...)
	lhs.singleList = append(lhs.singleList, arg.(*AsPathSet).singleList...)
	return nil
}

func (lhs *AsPathSet) Remove(arg DefinedSet) error {
	if lhs.Type() != arg.Type() {
		return fmt.Errorf("can't append to different type of defined-set")
	}
	newList := make([]*regexp.Regexp, 0, len(lhs.list))
	for _, x := range lhs.list {
		found := false
		for _, y := range arg.(*AsPathSet).list {
			if x.String() == y.String() {
				found = true
				break
			}
		}
		if !found {
			newList = append(newList, x)
		}
	}
	lhs.list = newList
	newSingleList := make([]*singleAsPathMatch, 0, len(lhs.singleList))
	for _, x := range lhs.singleList {
		found := false
		for _, y := range arg.(*AsPathSet).singleList {
			if x.Equal(y) {
				found = true
				break
			}
		}
		if !found {
			newSingleList = append(newSingleList, x)
		}
	}
	lhs.singleList = newSingleList
	return nil
}

func (lhs *AsPathSet) Replace(arg DefinedSet) error {
	rhs, ok := arg.(*AsPathSet)
	if !ok {
		return fmt.Errorf("type cast failed")
	}
	lhs.list = rhs.list
	lhs.singleList = rhs.singleList
	return nil
}

func (s *AsPathSet) List() []string {
	list := make([]string, 0, len(s.list)+len(s.singleList))
	for _, exp := range s.singleList {
		list = append(list, exp.String())
	}
	for _, exp := range s.list {
		list = append(list, exp.String())
	}
	return list
}

func (s *AsPathSet) ToConfig() *config.AsPathSet {
	return &config.AsPathSet{
		AsPathSetName: s.name,
		AsPathList:    s.List(),
	}
}

func (s *AsPathSet) String() string {
	return strings.Join(s.List(), "\n")
}

func (s *AsPathSet) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.ToConfig())
}

func NewAsPathSet(c config.AsPathSet) (*AsPathSet, error) {
	name := c.AsPathSetName
	if name == "" {
		if len(c.AsPathList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty as-path set name")
	}
	list := make([]*regexp.Regexp, 0, len(c.AsPathList))
	singleList := make([]*singleAsPathMatch, 0, len(c.AsPathList))
	for _, x := range c.AsPathList {
		if s := NewSingleAsPathMatch(x); s != nil {
			singleList = append(singleList, s)
		} else {
			exp, err := regexp.Compile(strings.Replace(x, "_", ASPATH_REGEXP_MAGIC, -1))
			if err != nil {
				return nil, fmt.Errorf("invalid regular expression: %s", x)
			}
			list = append(list, exp)
		}
	}
	return &AsPathSet{
		typ:        DEFINED_TYPE_AS_PATH,
		name:       name,
		list:       list,
		singleList: singleList,
	}, nil
}

type regExpSet struct {
	typ  DefinedType
	name string
	list []*regexp.Regexp
}

func (s *regExpSet) Name() string {
	return s.name
}

func (s *regExpSet) Type() DefinedType {
	return s.typ
}

func (lhs *regExpSet) Append(arg DefinedSet) error {
	if lhs.Type() != arg.Type() {
		return fmt.Errorf("can't append to different type of defined-set")
	}
	var list []*regexp.Regexp
	switch lhs.Type() {
	case DEFINED_TYPE_AS_PATH:
		list = arg.(*AsPathSet).list
	case DEFINED_TYPE_COMMUNITY:
		list = arg.(*CommunitySet).list
	case DEFINED_TYPE_EXT_COMMUNITY:
		list = arg.(*ExtCommunitySet).list
	case DEFINED_TYPE_LARGE_COMMUNITY:
		list = arg.(*LargeCommunitySet).list
	default:
		return fmt.Errorf("invalid defined-set type: %d", lhs.Type())
	}
	lhs.list = append(lhs.list, list...)
	return nil
}

func (lhs *regExpSet) Remove(arg DefinedSet) error {
	if lhs.Type() != arg.Type() {
		return fmt.Errorf("can't append to different type of defined-set")
	}
	var list []*regexp.Regexp
	switch lhs.Type() {
	case DEFINED_TYPE_AS_PATH:
		list = arg.(*AsPathSet).list
	case DEFINED_TYPE_COMMUNITY:
		list = arg.(*CommunitySet).list
	case DEFINED_TYPE_EXT_COMMUNITY:
		list = arg.(*ExtCommunitySet).list
	case DEFINED_TYPE_LARGE_COMMUNITY:
		list = arg.(*LargeCommunitySet).list
	default:
		return fmt.Errorf("invalid defined-set type: %d", lhs.Type())
	}
	ps := make([]*regexp.Regexp, 0, len(lhs.list))
	for _, x := range lhs.list {
		found := false
		for _, y := range list {
			if x.String() == y.String() {
				found = true
				break
			}
		}
		if !found {
			ps = append(ps, x)
		}
	}
	lhs.list = ps
	return nil
}

func (lhs *regExpSet) Replace(arg DefinedSet) error {
	switch c := arg.(type) {
	case *CommunitySet:
		lhs.list = c.list
	case *ExtCommunitySet:
		lhs.list = c.list
	case *LargeCommunitySet:
		lhs.list = c.list
	default:
		return fmt.Errorf("type cast failed")
	}
	return nil
}

type CommunitySet struct {
	regExpSet
}

func (s *CommunitySet) List() []string {
	list := make([]string, 0, len(s.list))
	for _, exp := range s.list {
		list = append(list, exp.String())
	}
	return list
}

func (s *CommunitySet) ToConfig() *config.CommunitySet {
	return &config.CommunitySet{
		CommunitySetName: s.name,
		CommunityList:    s.List(),
	}
}

func (s *CommunitySet) String() string {
	return strings.Join(s.List(), "\n")
}

func (s *CommunitySet) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.ToConfig())
}

var _regexpCommunity = regexp.MustCompile(`(\d+):(\d+)`)

func ParseCommunity(arg string) (uint32, error) {
	i, err := strconv.ParseUint(arg, 10, 32)
	if err == nil {
		return uint32(i), nil
	}

	elems := _regexpCommunity.FindStringSubmatch(arg)
	if len(elems) == 3 {
		fst, _ := strconv.ParseUint(elems[1], 10, 16)
		snd, _ := strconv.ParseUint(elems[2], 10, 16)
		return uint32(fst<<16 | snd), nil
	}
	for i, v := range bgp.WellKnownCommunityNameMap {
		if arg == v {
			return uint32(i), nil
		}
	}
	return 0, fmt.Errorf("failed to parse %s as community", arg)
}

func ParseExtCommunity(arg string) (bgp.ExtendedCommunityInterface, error) {
	var subtype bgp.ExtendedCommunityAttrSubType
	var value string
	elems := strings.SplitN(arg, ":", 2)

	isValidationState := func(s string) bool {
		s = strings.ToLower(s)
		r := s == bgp.VALIDATION_STATE_VALID.String()
		r = r || s == bgp.VALIDATION_STATE_NOT_FOUND.String()
		return r || s == bgp.VALIDATION_STATE_INVALID.String()
	}
	if len(elems) < 2 && (len(elems) < 1 && !isValidationState(elems[0])) {
		return nil, fmt.Errorf("invalid ext-community (rt|soo|encap|lb):<value> | valid | not-found | invalid")
	}
	if isValidationState(elems[0]) {
		subtype = bgp.EC_SUBTYPE_ORIGIN_VALIDATION
		value = elems[0]
	} else {
		switch strings.ToLower(elems[0]) {
		case "rt":
			subtype = bgp.EC_SUBTYPE_ROUTE_TARGET
		case "soo":
			subtype = bgp.EC_SUBTYPE_ROUTE_ORIGIN
		case "encap":
			subtype = bgp.EC_SUBTYPE_ENCAPSULATION
		case "lb":
			subtype = bgp.EC_SUBTYPE_LINK_BANDWIDTH
		default:
			return nil, fmt.Errorf("invalid ext-community (rt|soo|encap|lb):<value> | valid | not-found | invalid")
		}
		value = elems[1]
	}
	return bgp.ParseExtendedCommunity(subtype, value)
}

var _regexpCommunity2 = regexp.MustCompile(`^(\d+.)*\d+:\d+$`)

func ParseCommunityRegexp(arg string) (*regexp.Regexp, error) {
	i, err := strconv.ParseUint(arg, 10, 32)
	if err == nil {
		return regexp.Compile(fmt.Sprintf("^%d:%d$", i>>16, i&0x0000ffff))
	}

	if _regexpCommunity2.MatchString(arg) {
		return regexp.Compile(fmt.Sprintf("^%s$", arg))
	}

	for i, v := range bgp.WellKnownCommunityNameMap {
		if strings.Replace(strings.ToLower(arg), "_", "-", -1) == v {
			return regexp.Compile(fmt.Sprintf("^%d:%d$", i>>16, i&0x0000ffff))
		}
	}

	return regexp.Compile(arg)
}

func ParseExtCommunityRegexp(arg string) (bgp.ExtendedCommunityAttrSubType, *regexp.Regexp, error) {
	var subtype bgp.ExtendedCommunityAttrSubType
	elems := strings.SplitN(arg, ":", 2)
	if len(elems) < 2 {
		return subtype, nil, fmt.Errorf("invalid ext-community format([rt|soo|encap|lb]:<value>)")
	}
	switch strings.ToLower(elems[0]) {
	case "rt":
		subtype = bgp.EC_SUBTYPE_ROUTE_TARGET
	case "soo":
		subtype = bgp.EC_SUBTYPE_ROUTE_ORIGIN
	case "encap":
		subtype = bgp.EC_SUBTYPE_ENCAPSULATION
	case "lb":
		subtype = bgp.EC_SUBTYPE_LINK_BANDWIDTH
	default:
		return subtype, nil, fmt.Errorf("unknown ext-community subtype. rt, soo, encap, lb is supported")
	}
	exp, err := ParseCommunityRegexp(elems[1])
	return subtype, exp, err
}

func NewCommunitySet(c config.CommunitySet) (*CommunitySet, error) {
	name := c.CommunitySetName
	if name == "" {
		if len(c.CommunityList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty community set name")
	}
	list := make([]*regexp.Regexp, 0, len(c.CommunityList))
	for _, x := range c.CommunityList {
		exp, err := ParseCommunityRegexp(x)
		if err != nil {
			return nil, err
		}
		list = append(list, exp)
	}
	return &CommunitySet{
		regExpSet: regExpSet{
			typ:  DEFINED_TYPE_COMMUNITY,
			name: name,
			list: list,
		},
	}, nil
}

type ExtCommunitySet struct {
	regExpSet
	subtypeList []bgp.ExtendedCommunityAttrSubType
}

func (s *ExtCommunitySet) List() []string {
	list := make([]string, 0, len(s.list))
	f := func(idx int, arg string) string {
		switch s.subtypeList[idx] {
		case bgp.EC_SUBTYPE_ROUTE_TARGET:
			return fmt.Sprintf("rt:%s", arg)
		case bgp.EC_SUBTYPE_ROUTE_ORIGIN:
			return fmt.Sprintf("soo:%s", arg)
		case bgp.EC_SUBTYPE_ENCAPSULATION:
			return fmt.Sprintf("encap:%s", arg)
		case bgp.EC_SUBTYPE_ORIGIN_VALIDATION:
			return arg
		case bgp.EC_SUBTYPE_LINK_BANDWIDTH:
			return fmt.Sprintf("lb:%s", arg)
		default:
			return fmt.Sprintf("%d:%s", s.subtypeList[idx], arg)
		}
	}
	for idx, exp := range s.list {
		list = append(list, f(idx, exp.String()))
	}
	return list
}

func (s *ExtCommunitySet) ToConfig() *config.ExtCommunitySet {
	return &config.ExtCommunitySet{
		ExtCommunitySetName: s.name,
		ExtCommunityList:    s.List(),
	}
}

func (s *ExtCommunitySet) String() string {
	return strings.Join(s.List(), "\n")
}

func (s *ExtCommunitySet) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.ToConfig())
}

func NewExtCommunitySet(c config.ExtCommunitySet) (*ExtCommunitySet, error) {
	name := c.ExtCommunitySetName
	if name == "" {
		if len(c.ExtCommunityList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty ext-community set name")
	}
	list := make([]*regexp.Regexp, 0, len(c.ExtCommunityList))
	subtypeList := make([]bgp.ExtendedCommunityAttrSubType, 0, len(c.ExtCommunityList))
	for _, x := range c.ExtCommunityList {
		subtype, exp, err := ParseExtCommunityRegexp(x)
		if err != nil {
			return nil, err
		}
		list = append(list, exp)
		subtypeList = append(subtypeList, subtype)
	}
	return &ExtCommunitySet{
		regExpSet: regExpSet{
			typ:  DEFINED_TYPE_EXT_COMMUNITY,
			name: name,
			list: list,
		},
		subtypeList: subtypeList,
	}, nil
}

func (s *ExtCommunitySet) Append(arg DefinedSet) error {
	err := s.regExpSet.Append(arg)
	if err != nil {
		return err
	}
	sList := arg.(*ExtCommunitySet).subtypeList
	s.subtypeList = append(s.subtypeList, sList...)
	return nil
}

type LargeCommunitySet struct {
	regExpSet
}

func (s *LargeCommunitySet) List() []string {
	list := make([]string, 0, len(s.list))
	for _, exp := range s.list {
		list = append(list, exp.String())
	}
	return list
}

func (s *LargeCommunitySet) ToConfig() *config.LargeCommunitySet {
	return &config.LargeCommunitySet{
		LargeCommunitySetName: s.name,
		LargeCommunityList:    s.List(),
	}
}

func (s *LargeCommunitySet) String() string {
	return strings.Join(s.List(), "\n")
}

func (s *LargeCommunitySet) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.ToConfig())
}

var _regexpCommunityLarge = regexp.MustCompile(`\d+:\d+:\d+`)

func ParseLargeCommunityRegexp(arg string) (*regexp.Regexp, error) {
	if _regexpCommunityLarge.MatchString(arg) {
		return regexp.Compile(fmt.Sprintf("^%s$", arg))
	}
	exp, err := regexp.Compile(arg)
	if err != nil {
		return nil, fmt.Errorf("invalid large-community format: %v", err)
	}

	return exp, nil
}

func NewLargeCommunitySet(c config.LargeCommunitySet) (*LargeCommunitySet, error) {
	name := c.LargeCommunitySetName
	if name == "" {
		if len(c.LargeCommunityList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("empty large community set name")
	}
	list := make([]*regexp.Regexp, 0, len(c.LargeCommunityList))
	for _, x := range c.LargeCommunityList {
		exp, err := ParseLargeCommunityRegexp(x)
		if err != nil {
			return nil, err
		}
		list = append(list, exp)
	}
	return &LargeCommunitySet{
		regExpSet: regExpSet{
			typ:  DEFINED_TYPE_LARGE_COMMUNITY,
			name: name,
			list: list,
		},
	}, nil
}

type Condition interface {
	Name() string
	Type() ConditionType
	Evaluate(*Path, *PolicyOptions) bool
	Set() DefinedSet
}

type NextHopCondition struct {
	set *NextHopSet
}

func (c *NextHopCondition) Type() ConditionType {
	return CONDITION_NEXT_HOP
}

func (c *NextHopCondition) Set() DefinedSet {
	return c.set
}

func (c *NextHopCondition) Name() string { return "" }

func (c *NextHopCondition) String() string {
	return c.set.String()
}

// compare next-hop ipaddress of this condition and source address of path
// and, subsequent comparisons are skipped if that matches the conditions.
// If NextHopSet's length is zero, return true.
func (c *NextHopCondition) Evaluate(path *Path, options *PolicyOptions) bool {
	if len(c.set.list) == 0 {
		return true
	}

	nexthop := path.GetNexthop()

	// In cases where we advertise routes from iBGP to eBGP, we want to filter
	// on the "original" nexthop. The current paths' nexthop has already been
	// set and is ready to be advertised as per:
	// https://tools.ietf.org/html/rfc4271#section-5.1.3
	if options != nil && options.OldNextHop != nil &&
		!options.OldNextHop.IsUnspecified() && !options.OldNextHop.Equal(nexthop) {
		nexthop = options.OldNextHop
	}

	if nexthop == nil {
		return false
	}

	for _, n := range c.set.list {
		if n.Contains(nexthop) {
			return true
		}
	}

	return false
}

func NewNextHopCondition(c []string) (*NextHopCondition, error) {
	if len(c) == 0 {
		return nil, nil
	}

	list, err := NewNextHopSet(c)
	if err != nil {
		return nil, nil
	}

	return &NextHopCondition{
		set: list,
	}, nil
}

type PrefixCondition struct {
	set    *PrefixSet
	option MatchOption
}

func (c *PrefixCondition) Type() ConditionType {
	return CONDITION_PREFIX
}

func (c *PrefixCondition) Set() DefinedSet {
	return c.set
}

func (c *PrefixCondition) Option() MatchOption {
	return c.option
}

// compare prefixes in this condition and nlri of path and
// subsequent comparison is skipped if that matches the conditions.
// If PrefixList's length is zero, return true.
func (c *PrefixCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
	pathAfi, _ := bgp.RouteFamilyToAfiSafi(path.GetRouteFamily())
	cAfi, _ := bgp.RouteFamilyToAfiSafi(c.set.family)

	if cAfi != pathAfi {
		return false
	}

	r := nlriToIPNet(path.GetNlri())
	if r == nil {
		return false
	}
	ones, _ := r.Mask.Size()
	masklen := uint8(ones)
	result := false
	if _, ps, _ := c.set.tree.Match(r); ps != nil {
		for _, p := range ps.([]*Prefix) {
			if p.MasklengthRangeMin <= masklen && masklen <= p.MasklengthRangeMax {
				result = true
				break
			}
		}
	}

	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}

	return result
}

func (c *PrefixCondition) Name() string { return c.set.name }

func NewPrefixCondition(c config.MatchPrefixSet) (*PrefixCondition, error) {
	if c.PrefixSet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &PrefixCondition{
		set: &PrefixSet{
			name: c.PrefixSet,
		},
		option: o,
	}, nil
}

type NeighborCondition struct {
	set    *NeighborSet
	option MatchOption
}

func (c *NeighborCondition) Type() ConditionType {
	return CONDITION_NEIGHBOR
}

func (c *NeighborCondition) Set() DefinedSet {
	return c.set
}

func (c *NeighborCondition) Option() MatchOption {
	return c.option
}

// compare neighbor ipaddress of this condition and source address of path
// and, subsequent comparisons are skipped if that matches the conditions.
// If NeighborList's length is zero, return true.
func (c *NeighborCondition) Evaluate(path *Path, options *PolicyOptions) bool {
	if len(c.set.list) == 0 {
		return true
	}

	neighbor := path.GetSource().Address
	if options != nil && options.Info != nil && options.Info.Address != nil {
		neighbor = options.Info.Address
	}

	if neighbor == nil {
		return false
	}
	result := false
	for _, n := range c.set.list {
		if n.Contains(neighbor) {
			result = true
			break
		}
	}

	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}

	return result
}

func (c *NeighborCondition) Name() string { return c.set.name }

func NewNeighborCondition(c config.MatchNeighborSet) (*NeighborCondition, error) {
	if c.NeighborSet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &NeighborCondition{
		set: &NeighborSet{
			name: c.NeighborSet,
		},
		option: o,
	}, nil
}

type AsPathCondition struct {
	set    *AsPathSet
	option MatchOption
}

func (c *AsPathCondition) Type() ConditionType {
	return CONDITION_AS_PATH
}

func (c *AsPathCondition) Set() DefinedSet {
	return c.set
}

func (c *AsPathCondition) Option() MatchOption {
	return c.option
}

func (c *AsPathCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
	if len(c.set.singleList) > 0 {
		aspath := path.GetAsSeqList()
		for _, m := range c.set.singleList {
			result := m.Match(aspath)
			if c.option == MATCH_OPTION_ALL && !result {
				return false
			}
			if c.option == MATCH_OPTION_ANY && result {
				return true
			}
			if c.option == MATCH_OPTION_INVERT && result {
				return false
			}
		}
	}
	if len(c.set.list) > 0 {
		aspath := path.GetAsString()
		for _, r := range c.set.list {
			result := r.MatchString(aspath)
			if c.option == MATCH_OPTION_ALL && !result {
				return false
			}
			if c.option == MATCH_OPTION_ANY && result {
				return true
			}
			if c.option == MATCH_OPTION_INVERT && result {
				return false
			}
		}
	}
	if c.option == MATCH_OPTION_ANY {
		return false
	}
	return true
}

func (c *AsPathCondition) Name() string { return c.set.name }

func NewAsPathCondition(c config.MatchAsPathSet) (*AsPathCondition, error) {
	if c.AsPathSet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &AsPathCondition{
		set: &AsPathSet{
			name: c.AsPathSet,
		},
		option: o,
	}, nil
}

type CommunityCondition struct {
	set    *CommunitySet
	option MatchOption
}

func (c *CommunityCondition) Type() ConditionType {
	return CONDITION_COMMUNITY
}

func (c *CommunityCondition) Set() DefinedSet {
	return c.set
}

func (c *CommunityCondition) Option() MatchOption {
	return c.option
}

func (c *CommunityCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
	cs := path.GetCommunities()
	result := false
	for _, x := range c.set.list {
		result = false
		for _, y := range cs {
			if x.MatchString(fmt.Sprintf("%d:%d", y>>16, y&0x0000ffff)) {
				result = true
				break
			}
		}
		if c.option == MATCH_OPTION_ALL && !result {
			break
		}
		if (c.option == MATCH_OPTION_ANY || c.option == MATCH_OPTION_INVERT) && result {
			break
		}
	}
	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}
	return result
}

func (c *CommunityCondition) Name() string { return c.set.name }

func NewCommunityCondition(c config.MatchCommunitySet) (*CommunityCondition, error) {
	if c.CommunitySet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &CommunityCondition{
		set: &CommunitySet{
			regExpSet: regExpSet{
				name: c.CommunitySet,
			},
		},
		option: o,
	}, nil
}

type ExtCommunityCondition struct {
	set    *ExtCommunitySet
	option MatchOption
}

func (c *ExtCommunityCondition) Type() ConditionType {
	return CONDITION_EXT_COMMUNITY
}

func (c *ExtCommunityCondition) Set() DefinedSet {
	return c.set
}

func (c *ExtCommunityCondition) Option() MatchOption {
	return c.option
}

func (c *ExtCommunityCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
	es := path.GetExtCommunities()
	result := false
	for _, x := range es {
		result = false
		typ, subtype := x.GetTypes()
		// match only with transitive community. see RFC7153
		if typ >= 0x3f {
			continue
		}
		var xStr string
		for idx, y := range c.set.list {
			if subtype == c.set.subtypeList[idx] {
				if len(xStr) == 0 {
					// caching x.String() saves a lot of resources when matching against
					// a lot of conditions, link hundreds of RTs.
					xStr = x.String()
				}
				if y.MatchString(xStr) {
					result = true
					break
				}
			}
		}
		if c.option == MATCH_OPTION_ALL && !result {
			break
		}
		if c.option == MATCH_OPTION_ANY && result {
			break
		}
	}
	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}
	return result
}

func (c *ExtCommunityCondition) Name() string { return c.set.name }

func NewExtCommunityCondition(c config.MatchExtCommunitySet) (*ExtCommunityCondition, error) {
	if c.ExtCommunitySet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &ExtCommunityCondition{
		set: &ExtCommunitySet{
			regExpSet: regExpSet{
				name: c.ExtCommunitySet,
			},
		},
		option: o,
	}, nil
}

type LargeCommunityCondition struct {
	set    *LargeCommunitySet
	option MatchOption
}

func (c *LargeCommunityCondition) Type() ConditionType {
	return CONDITION_LARGE_COMMUNITY
}

func (c *LargeCommunityCondition) Set() DefinedSet {
	return c.set
}

func (c *LargeCommunityCondition) Option() MatchOption {
	return c.option
}

func (c *LargeCommunityCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
	result := false
	cs := path.GetLargeCommunities()
	for _, x := range c.set.list {
		result = false
		for _, y := range cs {
			if x.MatchString(y.String()) {
				result = true
				break
			}
		}
		if c.option == MATCH_OPTION_ALL && !result {
			break
		}
		if (c.option == MATCH_OPTION_ANY || c.option == MATCH_OPTION_INVERT) && result {
			break
		}
	}
	if c.option == MATCH_OPTION_INVERT {
		result = !result
	}
	return result
}

func (c *LargeCommunityCondition) Name() string { return c.set.name }

func NewLargeCommunityCondition(c config.MatchLargeCommunitySet) (*LargeCommunityCondition, error) {
	if c.LargeCommunitySet == "" {
		return nil, nil
	}
	o, err := NewMatchOption(c.MatchSetOptions)
	if err != nil {
		return nil, err
	}
	return &LargeCommunityCondition{
		set: &LargeCommunitySet{
			regExpSet: regExpSet{
				name: c.LargeCommunitySet,
			},
		},
		option: o,
	}, nil
}

type AsPathLengthCondition struct {
	length   uint32
	operator AttributeComparison
}

func (c *AsPathLengthCondition) Type() ConditionType {
	return CONDITION_AS_PATH_LENGTH
}

// compare AS_PATH length in the message's AS_PATH attribute with
// the one in condition.
func (c *AsPathLengthCondition) Evaluate(path *Path, _ *PolicyOptions) bool {

	length := uint32(path.GetAsPathLen())
	result := false
	switch c.operator {
	case ATTRIBUTE_EQ:
		result = c.length == length
	case ATTRIBUTE_GE:
		result = c.length <= length
	case ATTRIBUTE_LE:
		result = c.length >= length
	}

	return result
}

func (c *AsPathLengthCondition) Set() DefinedSet {
	return nil
}

func (c *AsPathLengthCondition) Name() string { return "" }

func (c *AsPathLengthCondition) String() string {
	return fmt.Sprintf("%s%d", c.operator, c.length)
}

func NewAsPathLengthCondition(c config.AsPathLength) (*AsPathLengthCondition, error) {
	if c.Value == 0 && c.Operator == "" {
		return nil, nil
	}
	var op AttributeComparison
	if i := c.Operator.ToInt(); i < 0 {
		return nil, fmt.Errorf("invalid as path length operator: %s", c.Operator)
	} else {
		// take mod 3 because we have extended openconfig attribute-comparison
		// for simple configuration. see config.AttributeComparison definition
		op = AttributeComparison(i % 3)
	}
	return &AsPathLengthCondition{
		length:   c.Value,
		operator: op,
	}, nil
}

type RpkiValidationCondition struct {
	result config.RpkiValidationResultType
}

func (c *RpkiValidationCondition) Type() ConditionType {
	return CONDITION_RPKI
}

func (c *RpkiValidationCondition) Evaluate(path *Path, options *PolicyOptions) bool {
	if options != nil && options.Validate != nil {
		return c.result == options.Validate(path).Status
	}
	return false
}

func (c *RpkiValidationCondition) Set() DefinedSet {
	return nil
}

func (c *RpkiValidationCondition) Name() string { return "" }

func (c *RpkiValidationCondition) String() string {
	return string(c.result)
}

func NewRpkiValidationCondition(c config.RpkiValidationResultType) (*RpkiValidationCondition, error) {
	if c == config.RpkiValidationResultType("") || c == config.RPKI_VALIDATION_RESULT_TYPE_NONE {
		return nil, nil
	}
	return &RpkiValidationCondition{
		result: c,
	}, nil
}

type RouteTypeCondition struct {
	typ config.RouteType
}

func (c *RouteTypeCondition) Type() ConditionType {
	return CONDITION_ROUTE_TYPE
}

func (c *RouteTypeCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
	switch c.typ {
	case config.ROUTE_TYPE_LOCAL:
		return path.IsLocal()
	case config.ROUTE_TYPE_INTERNAL:
		return !path.IsLocal() && path.IsIBGP()
	case config.ROUTE_TYPE_EXTERNAL:
		return !path.IsLocal() && !path.IsIBGP()
	}
	return false
}

func (c *RouteTypeCondition) Set() DefinedSet {
	return nil
}

func (c *RouteTypeCondition) Name() string { return "" }

func (c *RouteTypeCondition) String() string {
	return string(c.typ)
}

func NewRouteTypeCondition(c config.RouteType) (*RouteTypeCondition, error) {
	if string(c) == "" || c == config.ROUTE_TYPE_NONE {
		return nil, nil
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &RouteTypeCondition{
		typ: c,
	}, nil
}

type AfiSafiInCondition struct {
	routeFamilies []bgp.RouteFamily
}

func (c *AfiSafiInCondition) Type() ConditionType {
	return CONDITION_AFI_SAFI_IN
}

func (c *AfiSafiInCondition) Evaluate(path *Path, _ *PolicyOptions) bool {
	for _, rf := range c.routeFamilies {
		if path.GetRouteFamily() == rf {
			return true
		}
	}
	return false
}

func (c *AfiSafiInCondition) Set() DefinedSet {
	return nil
}

func (c *AfiSafiInCondition) Name() string { return "" }

func (c *AfiSafiInCondition) String() string {
	tmp := make([]string, 0, len(c.routeFamilies))
	for _, afiSafi := range c.routeFamilies {
		tmp = append(tmp, afiSafi.String())
	}
	return strings.Join(tmp, " ")
}

func NewAfiSafiInCondition(afiSafInConfig []config.AfiSafiType) (*AfiSafiInCondition, error) {
	if afiSafInConfig == nil {
		return nil, nil
	}

	routeFamilies := make([]bgp.RouteFamily, 0, len(afiSafInConfig))
	for _, afiSafiValue := range afiSafInConfig {
		if err := afiSafiValue.Validate(); err != nil {
			return nil, err
		}
		rf, err := bgp.GetRouteFamily(string(afiSafiValue))
		if err != nil {
			return nil, err
		}
		routeFamilies = append(routeFamilies, rf)
	}
	return &AfiSafiInCondition{
		routeFamilies: routeFamilies,
	}, nil
}

type Action interface {
	Type() ActionType
	Apply(*Path, *PolicyOptions) (*Path, error)
	String() string
}

type RoutingAction struct {
	AcceptRoute bool
}

func (a *RoutingAction) Type() ActionType {
	return ACTION_ROUTING
}

func (a *RoutingAction) Apply(path *Path, _ *PolicyOptions) (*Path, error) {
	if a.AcceptRoute {
		return path, nil
	}
	return nil, nil
}

func (a *RoutingAction) String() string {
	action := "reject"
	if a.AcceptRoute {
		action = "accept"
	}
	return action
}

func NewRoutingAction(c config.RouteDisposition) (*RoutingAction, error) {
	var accept bool
	switch c {
	case config.RouteDisposition(""), config.ROUTE_DISPOSITION_NONE:
		return nil, nil
	case config.ROUTE_DISPOSITION_ACCEPT_ROUTE:
		accept = true
	case config.ROUTE_DISPOSITION_REJECT_ROUTE:
		accept = false
	default:
		return nil, fmt.Errorf("invalid route disposition")
	}
	return &RoutingAction{
		AcceptRoute: accept,
	}, nil
}

type CommunityAction struct {
	action     config.BgpSetCommunityOptionType
	list       []uint32
	removeList []*regexp.Regexp
}

func RegexpRemoveCommunities(path *Path, exps []*regexp.Regexp) {
	comms := path.GetCommunities()
	newComms := make([]uint32, 0, len(comms))
	for _, comm := range comms {
		c := fmt.Sprintf("%d:%d", comm>>16, comm&0x0000ffff)
		match := false
		for _, exp := range exps {
			if exp.MatchString(c) {
				match = true
				break
			}
		}
		if !match {
			newComms = append(newComms, comm)
		}
	}
	path.SetCommunities(newComms, true)
}

func RegexpRemoveExtCommunities(path *Path, exps []*regexp.Regexp, subtypes []bgp.ExtendedCommunityAttrSubType) {
	comms := path.GetExtCommunities()
	newComms := make([]bgp.ExtendedCommunityInterface, 0, len(comms))
	for _, comm := range comms {
		match := false
		typ, subtype := comm.GetTypes()
		// match only with transitive community. see RFC7153
		if typ >= 0x3f {
			continue
		}
		for idx, exp := range exps {
			if subtype == subtypes[idx] && exp.MatchString(comm.String()) {
				match = true
				break
			}
		}
		if !match {
			newComms = append(newComms, comm)
		}
	}
	path.SetExtCommunities(newComms, true)
}

func RegexpRemoveLargeCommunities(path *Path, exps []*regexp.Regexp) {
	comms := path.GetLargeCommunities()
	newComms := make([]*bgp.LargeCommunity, 0, len(comms))
	for _, comm := range comms {
		c := comm.String()
		match := false
		for _, exp := range exps {
			if exp.MatchString(c) {
				match = true
				break
			}
		}
		if !match {
			newComms = append(newComms, comm)
		}
	}
	path.SetLargeCommunities(newComms, true)
}

func (a *CommunityAction) Type() ActionType {
	return ACTION_COMMUNITY
}

func (a *CommunityAction) Apply(path *Path, _ *PolicyOptions) (*Path, error) {
	switch a.action {
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD:
		path.SetCommunities(a.list, false)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE:
		RegexpRemoveCommunities(path, a.removeList)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE:
		path.SetCommunities(a.list, true)
	}
	return path, nil
}

func (a *CommunityAction) ToConfig() *config.SetCommunity {
	cs := make([]string, 0, len(a.list)+len(a.removeList))
	for _, comm := range a.list {
		c := fmt.Sprintf("%d:%d", comm>>16, comm&0x0000ffff)
		cs = append(cs, c)
	}
	for _, exp := range a.removeList {
		cs = append(cs, exp.String())
	}
	return &config.SetCommunity{
		Options:            string(a.action),
		SetCommunityMethod: config.SetCommunityMethod{CommunitiesList: cs},
	}
}

func (a *CommunityAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.ToConfig())
}

// TODO: this is not efficient use of regexp, probably slow
var _regexpCommunityReplaceString = regexp.MustCompile(`[\^\$]`)

func (a *CommunityAction) String() string {
	list := a.ToConfig().SetCommunityMethod.CommunitiesList
	l := _regexpCommunityReplaceString.ReplaceAllString(strings.Join(list, ", "), "")
	return fmt.Sprintf("%s[%s]", a.action, l)
}

func NewCommunityAction(c config.SetCommunity) (*CommunityAction, error) {
	a, ok := CommunityOptionValueMap[strings.ToLower(c.Options)]
	if !ok {
		if len(c.SetCommunityMethod.CommunitiesList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("invalid option name: %s", c.Options)
	}
	var list []uint32
	var removeList []*regexp.Regexp
	if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
		removeList = make([]*regexp.Regexp, 0, len(c.SetCommunityMethod.CommunitiesList))
	} else {
		list = make([]uint32, 0, len(c.SetCommunityMethod.CommunitiesList))
	}
	for _, x := range c.SetCommunityMethod.CommunitiesList {
		if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
			exp, err := ParseCommunityRegexp(x)
			if err != nil {
				return nil, err
			}
			removeList = append(removeList, exp)
		} else {
			comm, err := ParseCommunity(x)
			if err != nil {
				return nil, err
			}
			list = append(list, comm)
		}
	}
	return &CommunityAction{
		action:     a,
		list:       list,
		removeList: removeList,
	}, nil
}

type ExtCommunityAction struct {
	action      config.BgpSetCommunityOptionType
	list        []bgp.ExtendedCommunityInterface
	removeList  []*regexp.Regexp
	subtypeList []bgp.ExtendedCommunityAttrSubType
}

func (a *ExtCommunityAction) Type() ActionType {
	return ACTION_EXT_COMMUNITY
}

func (a *ExtCommunityAction) Apply(path *Path, _ *PolicyOptions) (*Path, error) {
	switch a.action {
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD:
		path.SetExtCommunities(a.list, false)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE:
		RegexpRemoveExtCommunities(path, a.removeList, a.subtypeList)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE:
		path.SetExtCommunities(a.list, true)
	}
	return path, nil
}

func (a *ExtCommunityAction) ToConfig() *config.SetExtCommunity {
	cs := make([]string, 0, len(a.list)+len(a.removeList))
	f := func(idx int, arg string) string {
		switch a.subtypeList[idx] {
		case bgp.EC_SUBTYPE_ROUTE_TARGET:
			return fmt.Sprintf("rt:%s", arg)
		case bgp.EC_SUBTYPE_ROUTE_ORIGIN:
			return fmt.Sprintf("soo:%s", arg)
		case bgp.EC_SUBTYPE_ENCAPSULATION:
			return fmt.Sprintf("encap:%s", arg)
		case bgp.EC_SUBTYPE_LINK_BANDWIDTH:
			return fmt.Sprintf("lb:%s", arg)
		case bgp.EC_SUBTYPE_ORIGIN_VALIDATION:
			return arg
		default:
			return fmt.Sprintf("%d:%s", a.subtypeList[idx], arg)
		}
	}
	for idx, c := range a.list {
		cs = append(cs, f(idx, c.String()))
	}
	for idx, exp := range a.removeList {
		cs = append(cs, f(idx, exp.String()))
	}
	return &config.SetExtCommunity{
		Options: string(a.action),
		SetExtCommunityMethod: config.SetExtCommunityMethod{
			CommunitiesList: cs,
		},
	}
}

func (a *ExtCommunityAction) String() string {
	list := a.ToConfig().SetExtCommunityMethod.CommunitiesList
	l := _regexpCommunityReplaceString.ReplaceAllString(strings.Join(list, ", "), "")
	return fmt.Sprintf("%s[%s]", a.action, l)
}

func (a *ExtCommunityAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.ToConfig())
}

func NewExtCommunityAction(c config.SetExtCommunity) (*ExtCommunityAction, error) {
	a, ok := CommunityOptionValueMap[strings.ToLower(c.Options)]
	if !ok {
		if len(c.SetExtCommunityMethod.CommunitiesList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("invalid option name: %s", c.Options)
	}
	var list []bgp.ExtendedCommunityInterface
	var removeList []*regexp.Regexp
	subtypeList := make([]bgp.ExtendedCommunityAttrSubType, 0, len(c.SetExtCommunityMethod.CommunitiesList))
	if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
		removeList = make([]*regexp.Regexp, 0, len(c.SetExtCommunityMethod.CommunitiesList))
	} else {
		list = make([]bgp.ExtendedCommunityInterface, 0, len(c.SetExtCommunityMethod.CommunitiesList))
	}
	for _, x := range c.SetExtCommunityMethod.CommunitiesList {
		if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
			subtype, exp, err := ParseExtCommunityRegexp(x)
			if err != nil {
				return nil, err
			}
			removeList = append(removeList, exp)
			subtypeList = append(subtypeList, subtype)
		} else {
			comm, err := ParseExtCommunity(x)
			if err != nil {
				return nil, err
			}
			list = append(list, comm)
			_, subtype := comm.GetTypes()
			subtypeList = append(subtypeList, subtype)
		}
	}
	return &ExtCommunityAction{
		action:      a,
		list:        list,
		removeList:  removeList,
		subtypeList: subtypeList,
	}, nil
}

type LargeCommunityAction struct {
	action     config.BgpSetCommunityOptionType
	list       []*bgp.LargeCommunity
	removeList []*regexp.Regexp
}

func (a *LargeCommunityAction) Type() ActionType {
	return ACTION_LARGE_COMMUNITY
}

func (a *LargeCommunityAction) Apply(path *Path, _ *PolicyOptions) (*Path, error) {
	switch a.action {
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_ADD:
		path.SetLargeCommunities(a.list, false)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE:
		RegexpRemoveLargeCommunities(path, a.removeList)
	case config.BGP_SET_COMMUNITY_OPTION_TYPE_REPLACE:
		path.SetLargeCommunities(a.list, true)
	}
	return path, nil
}

func (a *LargeCommunityAction) ToConfig() *config.SetLargeCommunity {
	cs := make([]string, 0, len(a.list)+len(a.removeList))
	for _, comm := range a.list {
		cs = append(cs, comm.String())
	}
	for _, exp := range a.removeList {
		cs = append(cs, exp.String())
	}
	return &config.SetLargeCommunity{
		SetLargeCommunityMethod: config.SetLargeCommunityMethod{CommunitiesList: cs},
		Options:                 config.BgpSetCommunityOptionType(a.action),
	}
}

func (a *LargeCommunityAction) String() string {
	list := a.ToConfig().SetLargeCommunityMethod.CommunitiesList
	l := _regexpCommunityReplaceString.ReplaceAllString(strings.Join(list, ", "), "")
	return fmt.Sprintf("%s[%s]", a.action, l)
}

func (a *LargeCommunityAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.ToConfig())
}

func NewLargeCommunityAction(c config.SetLargeCommunity) (*LargeCommunityAction, error) {
	a, ok := CommunityOptionValueMap[strings.ToLower(string(c.Options))]
	if !ok {
		if len(c.SetLargeCommunityMethod.CommunitiesList) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("invalid option name: %s", c.Options)
	}
	var list []*bgp.LargeCommunity
	var removeList []*regexp.Regexp
	if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
		removeList = make([]*regexp.Regexp, 0, len(c.SetLargeCommunityMethod.CommunitiesList))
	} else {
		list = make([]*bgp.LargeCommunity, 0, len(c.SetLargeCommunityMethod.CommunitiesList))
	}
	for _, x := range c.SetLargeCommunityMethod.CommunitiesList {
		if a == config.BGP_SET_COMMUNITY_OPTION_TYPE_REMOVE {
			exp, err := ParseLargeCommunityRegexp(x)
			if err != nil {
				return nil, err
			}
			removeList = append(removeList, exp)
		} else {
			comm, err := bgp.ParseLargeCommunity(x)
			if err != nil {
				return nil, err
			}
			list = append(list, comm)
		}
	}
	return &LargeCommunityAction{
		action:     a,
		list:       list,
		removeList: removeList,
	}, nil

}

type MedAction struct {
	value  int64
	action MedActionType
}

func (a *MedAction) Type() ActionType {
	return ACTION_MED
}

func (a *MedAction) Apply(path *Path, _ *PolicyOptions) (*Path, error) {
	var err error
	switch a.action {
	case MED_ACTION_MOD:
		err = path.SetMed(a.value, false)
	case MED_ACTION_REPLACE:
		err = path.SetMed(a.value, true)
	}
	if err != nil {
		return path, err
	}
	return path, nil
}

func (a *MedAction) ToConfig() config.BgpSetMedType {
	if a.action == MED_ACTION_MOD && a.value > 0 {
		return config.BgpSetMedType(fmt.Sprintf("+%d", a.value))
	}
	return config.BgpSetMedType(fmt.Sprintf("%d", a.value))
}

func (a *MedAction) String() string {
	return string(a.ToConfig())
}

func (a *MedAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.ToConfig())
}

var _regexpParseMedAction = regexp.MustCompile(`^(\+|\-)?(\d+)$`)

func NewMedAction(c config.BgpSetMedType) (*MedAction, error) {
	if string(c) == "" {
		return nil, nil
	}

	elems := _regexpParseMedAction.FindStringSubmatch(string(c))
	if len(elems) != 3 {
		return nil, fmt.Errorf("invalid med action format")
	}
	action := MED_ACTION_REPLACE
	switch elems[1] {
	case "+", "-":
		action = MED_ACTION_MOD
	}
	value, _ := strconv.ParseInt(string(c), 10, 64)
	return &MedAction{
		value:  value,
		action: action,
	}, nil
}

func NewMedActionFromApiStruct(action MedActionType, value int64) *MedAction {
	return &MedAction{action: action, value: value}
}

type LocalPrefAction struct {
	value uint32
}

func (a *LocalPrefAction) Type() ActionType {
	return ACTION_LOCAL_PREF
}

func (a *LocalPrefAction) Apply(path *Path, _ *PolicyOptions) (*Path, error) {
	path.setPathAttr(bgp.NewPathAttributeLocalPref(a.value))
	return path, nil
}

func (a *LocalPrefAction) ToConfig() uint32 {
	return a.value
}

func (a *LocalPrefAction) String() string {
	return fmt.Sprintf("%d", a.value)
}

func (a *LocalPrefAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.ToConfig())
}

func NewLocalPrefAction(value uint32) (*LocalPrefAction, error) {
	if value == 0 {
		return nil, nil
	}
	return &LocalPrefAction{
		value: value,
	}, nil
}

type AsPathPrependAction struct {
	asn         uint32
	useLeftMost bool
	repeat      uint8
}

func (a *AsPathPrependAction) Type() ActionType {
	return ACTION_AS_PATH_PREPEND
}

func (a *AsPathPrependAction) Apply(path *Path, option *PolicyOptions) (*Path, error) {
	var asn uint32
	if a.useLeftMost {
		aspath := path.GetAsSeqList()
		if len(aspath) == 0 {
			return path, nil
		}
		asn = aspath[0]
		if asn == 0 {
			return path, nil
		}
	} else {
		asn = a.asn
	}

	confed := option != nil && option.Info != nil && option.Info.Confederation
	path.PrependAsn(asn, a.repeat, confed)

	return path, nil
}

func (a *AsPathPrependAction) ToConfig() *config.SetAsPathPrepend {
	return &config.SetAsPathPrepend{
		RepeatN: uint8(a.repeat),
		As: func() string {
			if a.useLeftMost {
				return "last-as"
			}
			return fmt.Sprintf("%d", a.asn)
		}(),
	}
}

func (a *AsPathPrependAction) String() string {
	c := a.ToConfig()
	return fmt.Sprintf("prepend %s %d times", c.As, c.RepeatN)
}

func (a *AsPathPrependAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.ToConfig())
}

// NewAsPathPrependAction creates AsPathPrependAction object.
// If ASN cannot be parsed, nil will be returned.
func NewAsPathPrependAction(action config.SetAsPathPrepend) (*AsPathPrependAction, error) {
	a := &AsPathPrependAction{
		repeat: action.RepeatN,
	}
	switch action.As {
	case "":
		if a.repeat == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("specify as to prepend")
	case "last-as":
		a.useLeftMost = true
	default:
		asn, err := strconv.ParseUint(action.As, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("AS number string invalid")
		}
		a.asn = uint32(asn)
	}
	return a, nil
}

type NexthopAction struct {
	value     net.IP
	self      bool
	unchanged bool
}

func (a *NexthopAction) Type() ActionType {
	return ACTION_NEXTHOP
}

func (a *NexthopAction) Apply(path *Path, options *PolicyOptions) (*Path, error) {
	if a.self {
		if options != nil && options.Info != nil && options.Info.LocalAddress != nil {
			path.SetNexthop(options.Info.LocalAddress)
		}
		return path, nil
	}
	if a.unchanged {
		if options != nil && options.OldNextHop != nil {
			path.SetNexthop(options.OldNextHop)
		}
		return path, nil
	}
	path.SetNexthop(a.value)
	return path, nil
}

func (a *NexthopAction) ToConfig() config.BgpNextHopType {
	if a.self {
		return config.BgpNextHopType("self")
	}
	if a.unchanged {
		return config.BgpNextHopType("unchanged")
	}
	return config.BgpNextHopType(a.value.String())
}

func (a *NexthopAction) String() string {
	return string(a.ToConfig())
}

func (a *NexthopAction) MarshalJSON() ([]byte, error) {
	return json.Marshal(a.ToConfig())
}

func NewNexthopAction(c config.BgpNextHopType) (*NexthopAction, error) {
	switch strings.ToLower(string(c)) {
	case "":
		return nil, nil
	case "self":
		return &NexthopAction{
			self: true,
		}, nil
	case "unchanged":
		return &NexthopAction{
			unchanged: true,
		}, nil
	}
	addr := net.ParseIP(string(c))
	if addr == nil {
		return nil, fmt.Errorf("invalid ip address format: %s", string(c))
	}
	return &NexthopAction{
		value: addr,
	}, nil
}

type Statement struct {
	Name        string
	Conditions  []Condition
	RouteAction Action
	ModActions  []Action
}

// evaluate each condition in the statement according to MatchSetOptions
func (s *Statement) Evaluate(p *Path, options *PolicyOptions) bool {
	for _, c := range s.Conditions {
		if !c.Evaluate(p, options) {
			return false
		}
	}
	return true
}

func (s *Statement) Apply(logger log.Logger, path *Path, options *PolicyOptions) (RouteType, *Path) {
	result := s.Evaluate(path, options)
	if result {
		if len(s.ModActions) != 0 {
			// apply all modification actions
			path = path.Clone(path.IsWithdraw)
			for _, action := range s.ModActions {
				var err error
				path, err = action.Apply(path, options)
				if err != nil {
					logger.Warn("action failed",
						log.Fields{
							"Topic": "policy",
							"Error": err})
				}
			}
		}
		//Routing action
		if s.RouteAction == nil || reflect.ValueOf(s.RouteAction).IsNil() {
			return ROUTE_TYPE_NONE, path
		}
		p, _ := s.RouteAction.Apply(path, options)
		if p == nil {
			return ROUTE_TYPE_REJECT, path
		}
		return ROUTE_TYPE_ACCEPT, path
	}
	return ROUTE_TYPE_NONE, path
}

func (s *Statement) ToConfig() *config.Statement {
	return &config.Statement{
		Name: s.Name,
		Conditions: func() config.Conditions {
			cond := config.Conditions{}
			for _, c := range s.Conditions {
				switch v := c.(type) {
				case *PrefixCondition:
					cond.MatchPrefixSet = config.MatchPrefixSet{PrefixSet: v.set.Name(), MatchSetOptions: v.option.ConvertToMatchSetOptionsRestrictedType()}
				case *NeighborCondition:
					cond.MatchNeighborSet = config.MatchNeighborSet{NeighborSet: v.set.Name(), MatchSetOptions: v.option.ConvertToMatchSetOptionsRestrictedType()}
				case *AsPathLengthCondition:
					cond.BgpConditions.AsPathLength = config.AsPathLength{Operator: config.IntToAttributeComparisonMap[int(v.operator)], Value: v.length}
				case *AsPathCondition:
					cond.BgpConditions.MatchAsPathSet = config.MatchAsPathSet{AsPathSet: v.set.Name(), MatchSetOptions: config.IntToMatchSetOptionsTypeMap[int(v.option)]}
				case *CommunityCondition:
					cond.BgpConditions.MatchCommunitySet = config.MatchCommunitySet{CommunitySet: v.set.Name(), MatchSetOptions: config.IntToMatchSetOptionsTypeMap[int(v.option)]}
				case *ExtCommunityCondition:
					cond.BgpConditions.MatchExtCommunitySet = config.MatchExtCommunitySet{ExtCommunitySet: v.set.Name(), MatchSetOptions: config.IntToMatchSetOptionsTypeMap[int(v.option)]}
				case *LargeCommunityCondition:
					cond.BgpConditions.MatchLargeCommunitySet = config.MatchLargeCommunitySet{LargeCommunitySet: v.set.Name(), MatchSetOptions: config.IntToMatchSetOptionsTypeMap[int(v.option)]}
				case *NextHopCondition:
					cond.BgpConditions.NextHopInList = v.set.List()
				case *RpkiValidationCondition:
					cond.BgpConditions.RpkiValidationResult = v.result
				case *RouteTypeCondition:
					cond.BgpConditions.RouteType = v.typ
				case *AfiSafiInCondition:
					res := make([]config.AfiSafiType, 0, len(v.routeFamilies))
					for _, rf := range v.routeFamilies {
						res = append(res, config.AfiSafiType(rf.String()))
					}
					cond.BgpConditions.AfiSafiInList = res
				}
			}
			return cond
		}(),
		Actions: func() config.Actions {
			act := config.Actions{}
			if s.RouteAction != nil && !reflect.ValueOf(s.RouteAction).IsNil() {
				a := s.RouteAction.(*RoutingAction)
				if a.AcceptRoute {
					act.RouteDisposition = config.ROUTE_DISPOSITION_ACCEPT_ROUTE
				} else {
					act.RouteDisposition = config.ROUTE_DISPOSITION_REJECT_ROUTE
				}
			} else {
				act.RouteDisposition = config.ROUTE_DISPOSITION_NONE
			}
			for _, a := range s.ModActions {
				switch v := a.(type) {
				case *AsPathPrependAction:
					act.BgpActions.SetAsPathPrepend = *v.ToConfig()
				case *CommunityAction:
					act.BgpActions.SetCommunity = *v.ToConfig()
				case *ExtCommunityAction:
					act.BgpActions.SetExtCommunity = *v.ToConfig()
				case *LargeCommunityAction:
					act.BgpActions.SetLargeCommunity = *v.ToConfig()
				case *MedAction:
					act.BgpActions.SetMed = v.ToConfig()
				case *LocalPrefAction:
					act.BgpActions.SetLocalPref = v.ToConfig()
				case *NexthopAction:
					act.BgpActions.SetNextHop = v.ToConfig()
				}
			}
			return act
		}(),
	}
}

func (s *Statement) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.ToConfig())
}

type opType int

const (
	ADD opType = iota
	REMOVE
	REPLACE
)

func (lhs *Statement) mod(op opType, rhs *Statement) error {
	cs := make([]Condition, len(lhs.Conditions))
	copy(cs, lhs.Conditions)
	ra := lhs.RouteAction
	as := make([]Action, len(lhs.ModActions))
	copy(as, lhs.ModActions)
	for _, x := range rhs.Conditions {
		var c Condition
		i := 0
		for idx, y := range lhs.Conditions {
			if x.Type() == y.Type() {
				c = y
				i = idx
				break
			}
		}
		switch op {
		case ADD:
			if c != nil {
				return fmt.Errorf("condition %d is already set", x.Type())
			}
			if cs == nil {
				cs = make([]Condition, 0, len(rhs.Conditions))
			}
			cs = append(cs, x)
		case REMOVE:
			if c == nil {
				return fmt.Errorf("condition %d is not set", x.Type())
			}
			cs = append(cs[:i], cs[i+1:]...)
			if len(cs) == 0 {
				cs = nil
			}
		case REPLACE:
			if c == nil {
				return fmt.Errorf("condition %d is not set", x.Type())
			}
			cs[i] = x
		}
	}
	if rhs.RouteAction != nil && !reflect.ValueOf(rhs.RouteAction).IsNil() {
		switch op {
		case ADD:
			if lhs.RouteAction != nil && !reflect.ValueOf(lhs.RouteAction).IsNil() {
				return fmt.Errorf("route action is already set")
			}
			ra = rhs.RouteAction
		case REMOVE:
			if lhs.RouteAction == nil || reflect.ValueOf(lhs.RouteAction).IsNil() {
				return fmt.Errorf("route action is not set")
			}
			ra = nil
		case REPLACE:
			if lhs.RouteAction == nil || reflect.ValueOf(lhs.RouteAction).IsNil() {
				return fmt.Errorf("route action is not set")
			}
			ra = rhs.RouteAction
		}
	}
	for _, x := range rhs.ModActions {
		var a Action
		i := 0
		for idx, y := range lhs.ModActions {
			if x.Type() == y.Type() {
				a = y
				i = idx
				break
			}
		}
		switch op {
		case ADD:
			if a != nil {
				return fmt.Errorf("action %d is already set", x.Type())
			}
			if as == nil {
				as = make([]Action, 0, len(rhs.ModActions))
			}
			as = append(as, x)
		case REMOVE:
			if a == nil {
				return fmt.Errorf("action %d is not set", x.Type())
			}
			as = append(as[:i], as[i+1:]...)
			if len(as) == 0 {
				as = nil
			}
		case REPLACE:
			if a == nil {
				return fmt.Errorf("action %d is not set", x.Type())
			}
			as[i] = x
		}
	}
	lhs.Conditions = cs
	lhs.RouteAction = ra
	lhs.ModActions = as
	return nil
}

func (lhs *Statement) Add(rhs *Statement) error {
	return lhs.mod(ADD, rhs)
}

func (lhs *Statement) Remove(rhs *Statement) error {
	return lhs.mod(REMOVE, rhs)
}

func (lhs *Statement) Replace(rhs *Statement) error {
	return lhs.mod(REPLACE, rhs)
}

func NewStatement(c config.Statement) (*Statement, error) {
	if c.Name == "" {
		return nil, fmt.Errorf("empty statement name")
	}
	var ra Action
	var as []Action
	var cs []Condition
	var err error
	cfs := []func() (Condition, error){
		func() (Condition, error) {
			return NewPrefixCondition(c.Conditions.MatchPrefixSet)
		},
		func() (Condition, error) {
			return NewNeighborCondition(c.Conditions.MatchNeighborSet)
		},
		func() (Condition, error) {
			return NewAsPathLengthCondition(c.Conditions.BgpConditions.AsPathLength)
		},
		func() (Condition, error) {
			return NewRpkiValidationCondition(c.Conditions.BgpConditions.RpkiValidationResult)
		},
		func() (Condition, error) {
			return NewRouteTypeCondition(c.Conditions.BgpConditions.RouteType)
		},
		func() (Condition, error) {
			return NewAsPathCondition(c.Conditions.BgpConditions.MatchAsPathSet)
		},
		func() (Condition, error) {
			return NewCommunityCondition(c.Conditions.BgpConditions.MatchCommunitySet)
		},
		func() (Condition, error) {
			return NewExtCommunityCondition(c.Conditions.BgpConditions.MatchExtCommunitySet)
		},
		func() (Condition, error) {
			return NewLargeCommunityCondition(c.Conditions.BgpConditions.MatchLargeCommunitySet)
		},
		func() (Condition, error) {
			return NewNextHopCondition(c.Conditions.BgpConditions.NextHopInList)
		},
		func() (Condition, error) {
			return NewAfiSafiInCondition(c.Conditions.BgpConditions.AfiSafiInList)
		},
	}
	cs = make([]Condition, 0, len(cfs))
	for _, f := range cfs {
		c, err := f()
		if err != nil {
			return nil, err
		}
		if !reflect.ValueOf(c).IsNil() {
			cs = append(cs, c)
		}
	}
	ra, err = NewRoutingAction(c.Actions.RouteDisposition)
	if err != nil {
		return nil, err
	}
	afs := []func() (Action, error){
		func() (Action, error) {
			return NewCommunityAction(c.Actions.BgpActions.SetCommunity)
		},
		func() (Action, error) {
			return NewExtCommunityAction(c.Actions.BgpActions.SetExtCommunity)
		},
		func() (Action, error) {
			return NewLargeCommunityAction(c.Actions.BgpActions.SetLargeCommunity)
		},
		func() (Action, error) {
			return NewMedAction(c.Actions.BgpActions.SetMed)
		},
		func() (Action, error) {
			return NewLocalPrefAction(c.Actions.BgpActions.SetLocalPref)
		},
		func() (Action, error) {
			return NewAsPathPrependAction(c.Actions.BgpActions.SetAsPathPrepend)
		},
		func() (Action, error) {
			return NewNexthopAction(c.Actions.BgpActions.SetNextHop)
		},
	}
	as = make([]Action, 0, len(afs))
	for _, f := range afs {
		a, err := f()
		if err != nil {
			return nil, err
		}
		if !reflect.ValueOf(a).IsNil() {
			as = append(as, a)
		}
	}
	return &Statement{
		Name:        c.Name,
		Conditions:  cs,
		RouteAction: ra,
		ModActions:  as,
	}, nil
}

type Policy struct {
	Name       string
	Statements []*Statement
}

// Compare path with a policy's condition in stored order in the policy.
// If a condition match, then this function stops evaluation and
// subsequent conditions are skipped.
func (p *Policy) Apply(logger log.Logger, path *Path, options *PolicyOptions) (RouteType, *Path) {
	for _, stmt := range p.Statements {
		var result RouteType
		result, path = stmt.Apply(logger, path, options)
		if result != ROUTE_TYPE_NONE {
			return result, path
		}
	}
	return ROUTE_TYPE_NONE, path
}

func (p *Policy) ToConfig() *config.PolicyDefinition {
	ss := make([]config.Statement, 0, len(p.Statements))
	for _, s := range p.Statements {
		ss = append(ss, *s.ToConfig())
	}
	return &config.PolicyDefinition{
		Name:       p.Name,
		Statements: ss,
	}
}

func (p *Policy) FillUp(m map[string]*Statement) error {
	stmts := make([]*Statement, 0, len(p.Statements))
	for _, x := range p.Statements {
		y, ok := m[x.Name]
		if !ok {
			return fmt.Errorf("not found statement %s", x.Name)
		}
		stmts = append(stmts, y)
	}
	p.Statements = stmts
	return nil
}

func (lhs *Policy) Add(rhs *Policy) error {
	lhs.Statements = append(lhs.Statements, rhs.Statements...)
	return nil
}

func (lhs *Policy) Remove(rhs *Policy) error {
	stmts := make([]*Statement, 0, len(lhs.Statements))
	for _, x := range lhs.Statements {
		found := false
		for _, y := range rhs.Statements {
			if x.Name == y.Name {
				found = true
				break
			}
		}
		if !found {
			stmts = append(stmts, x)
		}
	}
	lhs.Statements = stmts
	return nil
}

func (lhs *Policy) Replace(rhs *Policy) error {
	lhs.Statements = rhs.Statements
	return nil
}

func (p *Policy) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ToConfig())
}

func NewPolicy(c config.PolicyDefinition) (*Policy, error) {
	if c.Name == "" {
		return nil, fmt.Errorf("empty policy name")
	}
	var st []*Statement
	stmts := c.Statements
	if len(stmts) != 0 {
		st = make([]*Statement, 0, len(stmts))
		for idx, stmt := range stmts {
			if stmt.Name == "" {
				stmt.Name = fmt.Sprintf("%s_stmt%d", c.Name, idx)
			}
			s, err := NewStatement(stmt)
			if err != nil {
				return nil, err
			}
			st = append(st, s)
		}
	}
	return &Policy{
		Name:       c.Name,
		Statements: st,
	}, nil
}

type Policies []*Policy

func (p Policies) Len() int {
	return len(p)
}

func (p Policies) Swap(i, j int) {
	p[i], p[j] = p[j], p[i]
}

func (p Policies) Less(i, j int) bool {
	return p[i].Name < p[j].Name
}

type Assignment struct {
	importPolicies      []*Policy
	defaultImportPolicy RouteType
	exportPolicies      []*Policy
	defaultExportPolicy RouteType
}

type RoutingPolicy struct {
	definedSetMap DefinedSetMap
	policyMap     map[string]*Policy
	statementMap  map[string]*Statement
	assignmentMap map[string]*Assignment
	mu            sync.RWMutex
	logger        log.Logger
}

func (r *RoutingPolicy) ApplyPolicy(id string, dir PolicyDirection, before *Path, options *PolicyOptions) *Path {
	if before == nil {
		return nil
	}

	if before.IsWithdraw {
		return before
	}
	result := ROUTE_TYPE_NONE
	after := before

	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, p := range r.getPolicy(id, dir) {
		result, after = p.Apply(r.logger, after, options)
		if result != ROUTE_TYPE_NONE {
			break
		}
	}
	if result == ROUTE_TYPE_NONE {
		result = r.getDefaultPolicy(id, dir)
	}
	switch result {
	case ROUTE_TYPE_ACCEPT:
		return after
	default:
		return nil
	}
}

func (r *RoutingPolicy) getPolicy(id string, dir PolicyDirection) []*Policy {
	a, ok := r.assignmentMap[id]
	if !ok {
		return nil
	}
	switch dir {
	case POLICY_DIRECTION_IMPORT:
		return a.importPolicies
	case POLICY_DIRECTION_EXPORT:
		return a.exportPolicies
	default:
		return nil
	}
}

func (r *RoutingPolicy) getDefaultPolicy(id string, dir PolicyDirection) RouteType {
	a, ok := r.assignmentMap[id]
	if !ok {
		return ROUTE_TYPE_NONE
	}
	switch dir {
	case POLICY_DIRECTION_IMPORT:
		return a.defaultImportPolicy
	case POLICY_DIRECTION_EXPORT:
		return a.defaultExportPolicy
	default:
		return ROUTE_TYPE_NONE
	}

}

func (r *RoutingPolicy) setPolicy(id string, dir PolicyDirection, policies []*Policy) error {
	a, ok := r.assignmentMap[id]
	if !ok {
		a = &Assignment{}
	}
	switch dir {
	case POLICY_DIRECTION_IMPORT:
		a.importPolicies = policies
	case POLICY_DIRECTION_EXPORT:
		a.exportPolicies = policies
	}
	r.assignmentMap[id] = a
	return nil
}

func (r *RoutingPolicy) setDefaultPolicy(id string, dir PolicyDirection, typ RouteType) error {
	a, ok := r.assignmentMap[id]
	if !ok {
		a = &Assignment{}
	}
	switch dir {
	case POLICY_DIRECTION_IMPORT:
		a.defaultImportPolicy = typ
	case POLICY_DIRECTION_EXPORT:
		a.defaultExportPolicy = typ
	}
	r.assignmentMap[id] = a
	return nil
}

func (r *RoutingPolicy) getAssignmentFromConfig(dir PolicyDirection, a config.ApplyPolicy) ([]*Policy, RouteType, error) {
	var names []string
	var cdef config.DefaultPolicyType
	def := ROUTE_TYPE_ACCEPT
	c := a.Config
	switch dir {
	case POLICY_DIRECTION_IMPORT:
		names = c.ImportPolicyList
		cdef = c.DefaultImportPolicy
	case POLICY_DIRECTION_EXPORT:
		names = c.ExportPolicyList
		cdef = c.DefaultExportPolicy
	default:
		return nil, def, fmt.Errorf("invalid policy direction")
	}
	if cdef == config.DEFAULT_POLICY_TYPE_REJECT_ROUTE {
		def = ROUTE_TYPE_REJECT
	}
	ps := make([]*Policy, 0, len(names))
	seen := make(map[string]bool)
	for _, name := range names {
		p, ok := r.policyMap[name]
		if !ok {
			return nil, def, fmt.Errorf("not found policy %s", name)
		}
		if seen[name] {
			return nil, def, fmt.Errorf("duplicated policy %s", name)
		}
		seen[name] = true
		ps = append(ps, p)
	}
	return ps, def, nil
}

func (r *RoutingPolicy) validateCondition(v Condition) (err error) {
	switch v.Type() {
	case CONDITION_PREFIX:
		m := r.definedSetMap[DEFINED_TYPE_PREFIX]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found prefix set %s", v.Name())
		} else {
			c := v.(*PrefixCondition)
			c.set = i.(*PrefixSet)
		}
	case CONDITION_NEIGHBOR:
		m := r.definedSetMap[DEFINED_TYPE_NEIGHBOR]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found neighbor set %s", v.Name())
		} else {
			c := v.(*NeighborCondition)
			c.set = i.(*NeighborSet)
		}
	case CONDITION_AS_PATH:
		m := r.definedSetMap[DEFINED_TYPE_AS_PATH]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found as path set %s", v.Name())
		} else {
			c := v.(*AsPathCondition)
			c.set = i.(*AsPathSet)
		}
	case CONDITION_COMMUNITY:
		m := r.definedSetMap[DEFINED_TYPE_COMMUNITY]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found community set %s", v.Name())
		} else {
			c := v.(*CommunityCondition)
			c.set = i.(*CommunitySet)
		}
	case CONDITION_EXT_COMMUNITY:
		m := r.definedSetMap[DEFINED_TYPE_EXT_COMMUNITY]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found ext-community set %s", v.Name())
		} else {
			c := v.(*ExtCommunityCondition)
			c.set = i.(*ExtCommunitySet)
		}
	case CONDITION_LARGE_COMMUNITY:
		m := r.definedSetMap[DEFINED_TYPE_LARGE_COMMUNITY]
		if i, ok := m[v.Name()]; !ok {
			return fmt.Errorf("not found large-community set %s", v.Name())
		} else {
			c := v.(*LargeCommunityCondition)
			c.set = i.(*LargeCommunitySet)
		}
	case CONDITION_NEXT_HOP:
	case CONDITION_AFI_SAFI_IN:
	case CONDITION_AS_PATH_LENGTH:
	case CONDITION_RPKI:
	}
	return nil
}

func (r *RoutingPolicy) inUse(d DefinedSet) bool {
	name := d.Name()
	for _, p := range r.policyMap {
		for _, s := range p.Statements {
			for _, c := range s.Conditions {
				if c.Set() != nil && c.Set().Name() == name {
					return true
				}
			}
		}
	}
	return false
}

func (r *RoutingPolicy) statementInUse(x *Statement) bool {
	for _, p := range r.policyMap {
		for _, y := range p.Statements {
			if x.Name == y.Name {
				return true
			}
		}
	}
	return false
}

func (r *RoutingPolicy) reload(c config.RoutingPolicy) error {
	dmap := make(map[DefinedType]map[string]DefinedSet)
	dmap[DEFINED_TYPE_PREFIX] = make(map[string]DefinedSet)
	d := c.DefinedSets
	for _, x := range d.PrefixSets {
		y, err := NewPrefixSet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty prefix set")
		}
		dmap[DEFINED_TYPE_PREFIX][y.Name()] = y
	}
	dmap[DEFINED_TYPE_NEIGHBOR] = make(map[string]DefinedSet)
	for _, x := range d.NeighborSets {
		y, err := NewNeighborSet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty neighbor set")
		}
		dmap[DEFINED_TYPE_NEIGHBOR][y.Name()] = y
	}
	//	dmap[DEFINED_TYPE_TAG] = make(map[string]DefinedSet)
	//	for _, x := range c.DefinedSets.TagSets{
	//		y, err := NewTagSet(x)
	//		if err != nil {
	//			return nil, err
	//		}
	//		dmap[DEFINED_TYPE_TAG][y.Name()] = y
	//	}
	bd := c.DefinedSets.BgpDefinedSets
	dmap[DEFINED_TYPE_AS_PATH] = make(map[string]DefinedSet)
	for _, x := range bd.AsPathSets {
		y, err := NewAsPathSet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty as path set")
		}
		dmap[DEFINED_TYPE_AS_PATH][y.Name()] = y
	}
	dmap[DEFINED_TYPE_COMMUNITY] = make(map[string]DefinedSet)
	for _, x := range bd.CommunitySets {
		y, err := NewCommunitySet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty community set")
		}
		dmap[DEFINED_TYPE_COMMUNITY][y.Name()] = y
	}
	dmap[DEFINED_TYPE_EXT_COMMUNITY] = make(map[string]DefinedSet)
	for _, x := range bd.ExtCommunitySets {
		y, err := NewExtCommunitySet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty ext-community set")
		}
		dmap[DEFINED_TYPE_EXT_COMMUNITY][y.Name()] = y
	}
	dmap[DEFINED_TYPE_LARGE_COMMUNITY] = make(map[string]DefinedSet)
	for _, x := range bd.LargeCommunitySets {
		y, err := NewLargeCommunitySet(x)
		if err != nil {
			return err
		}
		if y == nil {
			return fmt.Errorf("empty large-community set")
		}
		dmap[DEFINED_TYPE_LARGE_COMMUNITY][y.Name()] = y
	}

	pmap := make(map[string]*Policy)
	smap := make(map[string]*Statement)
	for _, x := range c.PolicyDefinitions {
		y, err := NewPolicy(x)
		if err != nil {
			return err
		}
		if _, ok := pmap[y.Name]; ok {
			return fmt.Errorf("duplicated policy name. policy name must be unique")
		}
		pmap[y.Name] = y
		for _, s := range y.Statements {
			_, ok := smap[s.Name]
			if ok {
				return fmt.Errorf("duplicated statement name. statement name must be unique")
			}
			smap[s.Name] = s
		}
	}

	// hacky
	oldMap := r.definedSetMap
	r.definedSetMap = dmap
	for _, y := range pmap {
		for _, s := range y.Statements {
			for _, c := range s.Conditions {
				if err := r.validateCondition(c); err != nil {
					r.definedSetMap = oldMap
					return err
				}
			}
		}
	}

	r.definedSetMap = dmap
	r.policyMap = pmap
	r.statementMap = smap
	r.assignmentMap = make(map[string]*Assignment)
	// allow all routes coming in and going out by default
	r.setDefaultPolicy(GLOBAL_RIB_NAME, POLICY_DIRECTION_IMPORT, ROUTE_TYPE_ACCEPT)
	r.setDefaultPolicy(GLOBAL_RIB_NAME, POLICY_DIRECTION_EXPORT, ROUTE_TYPE_ACCEPT)
	return nil
}

func (r *RoutingPolicy) GetDefinedSet(typ DefinedType, name string) (*config.DefinedSets, error) {
	dl, err := func() (DefinedSetList, error) {
		r.mu.RLock()
		defer r.mu.RUnlock()

		set, ok := r.definedSetMap[typ]
		if !ok {
			return nil, fmt.Errorf("invalid defined-set type: %d", typ)
		}

		var dl DefinedSetList
		for _, s := range set {
			dl = append(dl, s)
		}
		return dl, nil
	}()
	if err != nil {
		return nil, err
	}

	sort.Sort(dl)

	sets := &config.DefinedSets{
		PrefixSets:   make([]config.PrefixSet, 0),
		NeighborSets: make([]config.NeighborSet, 0),
		BgpDefinedSets: config.BgpDefinedSets{
			CommunitySets:      make([]config.CommunitySet, 0),
			ExtCommunitySets:   make([]config.ExtCommunitySet, 0),
			LargeCommunitySets: make([]config.LargeCommunitySet, 0),
			AsPathSets:         make([]config.AsPathSet, 0),
		},
	}
	for _, s := range dl {
		if name != "" && s.Name() != name {
			continue
		}
		switch v := s.(type) {
		case *PrefixSet:
			sets.PrefixSets = append(sets.PrefixSets, *v.ToConfig())
		case *NeighborSet:
			sets.NeighborSets = append(sets.NeighborSets, *v.ToConfig())
		case *CommunitySet:
			sets.BgpDefinedSets.CommunitySets = append(sets.BgpDefinedSets.CommunitySets, *v.ToConfig())
		case *ExtCommunitySet:
			sets.BgpDefinedSets.ExtCommunitySets = append(sets.BgpDefinedSets.ExtCommunitySets, *v.ToConfig())
		case *LargeCommunitySet:
			sets.BgpDefinedSets.LargeCommunitySets = append(sets.BgpDefinedSets.LargeCommunitySets, *v.ToConfig())
		case *AsPathSet:
			sets.BgpDefinedSets.AsPathSets = append(sets.BgpDefinedSets.AsPathSets, *v.ToConfig())
		}
	}
	return sets, nil
}

func (r *RoutingPolicy) AddDefinedSet(s DefinedSet) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if m, ok := r.definedSetMap[s.Type()]; !ok {
		return fmt.Errorf("invalid defined-set type: %d", s.Type())
	} else {
		if d, ok := m[s.Name()]; ok {
			if err := d.Append(s); err != nil {
				return err
			}
		} else {
			m[s.Name()] = s
		}
	}
	return nil
}

func (r *RoutingPolicy) DeleteDefinedSet(a DefinedSet, all bool) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if m, ok := r.definedSetMap[a.Type()]; !ok {
		err = fmt.Errorf("invalid defined-set type: %d", a.Type())
	} else {
		d, ok := m[a.Name()]
		if !ok {
			return fmt.Errorf("not found defined-set: %s", a.Name())
		}
		if all {
			if r.inUse(d) {
				err = fmt.Errorf("can't delete. defined-set %s is in use", a.Name())
			} else {
				delete(m, a.Name())
			}
		} else {
			err = d.Remove(a)
		}
	}
	return err
}

func (r *RoutingPolicy) GetStatement(name string) []*config.Statement {
	r.mu.RLock()
	defer r.mu.RUnlock()

	l := make([]*config.Statement, 0, len(r.statementMap))
	for _, st := range r.statementMap {
		if name != "" && name != st.Name {
			continue
		}
		l = append(l, st.ToConfig())
	}
	return l
}

func (r *RoutingPolicy) AddStatement(st *Statement) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, c := range st.Conditions {
		if err = r.validateCondition(c); err != nil {
			return
		}
	}
	m := r.statementMap
	name := st.Name
	if d, ok := m[name]; ok {
		err = d.Add(st)
	} else {
		m[name] = st
	}

	return err
}

func (r *RoutingPolicy) DeleteStatement(st *Statement, all bool) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	m := r.statementMap
	name := st.Name
	if d, ok := m[name]; ok {
		if all {
			if r.statementInUse(d) {
				err = fmt.Errorf("can't delete. statement %s is in use", name)
			} else {
				delete(m, name)
			}
		} else {
			err = d.Remove(st)
		}
	} else {
		err = fmt.Errorf("not found statement: %s", name)
	}
	return err
}

func (r *RoutingPolicy) GetPolicy(name string) []*config.PolicyDefinition {
	ps := func() Policies {
		r.mu.RLock()
		defer r.mu.RUnlock()

		var ps Policies
		for _, p := range r.policyMap {
			if name != "" && name != p.Name {
				continue
			}
			ps = append(ps, p)
		}
		return ps
	}()

	sort.Sort(ps)

	l := make([]*config.PolicyDefinition, 0, len(ps))
	for _, p := range ps {
		l = append(l, p.ToConfig())
	}
	return l
}

func (r *RoutingPolicy) AddPolicy(x *Policy, refer bool) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, st := range x.Statements {
		for _, c := range st.Conditions {
			if err = r.validateCondition(c); err != nil {
				return
			}
		}
	}

	pMap := r.policyMap
	sMap := r.statementMap
	name := x.Name
	y, ok := pMap[name]
	if refer {
		err = x.FillUp(sMap)
	} else {
		for _, st := range x.Statements {
			if _, ok := sMap[st.Name]; ok {
				err = fmt.Errorf("statement %s already defined", st.Name)
				return
			}
			sMap[st.Name] = st
		}
	}
	if ok {
		err = y.Add(x)
	} else {
		pMap[name] = x
	}

	return err
}

func (r *RoutingPolicy) DeletePolicy(x *Policy, all, preserve bool, activeId []string) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	pMap := r.policyMap
	sMap := r.statementMap
	name := x.Name
	y, ok := pMap[name]
	if !ok {
		err = fmt.Errorf("not found policy: %s", name)
		return
	}
	inUse := func(ids []string) bool {
		for _, id := range ids {
			for _, dir := range []PolicyDirection{POLICY_DIRECTION_EXPORT, POLICY_DIRECTION_EXPORT} {
				for _, y := range r.getPolicy(id, dir) {
					if x.Name == y.Name {
						return true
					}
				}
			}
		}
		return false
	}

	if all {
		if inUse(activeId) {
			err = fmt.Errorf("can't delete. policy %s is in use", name)
			return
		}
		r.logger.Debug("delete policy",
			log.Fields{
				"Topic": "Policy",
				"Key":   name})
		delete(pMap, name)
	} else {
		err = y.Remove(x)
	}
	if err == nil && !preserve {
		for _, st := range y.Statements {
			if !r.statementInUse(st) {
				r.logger.Debug("delete unused statement",
					log.Fields{
						"Topic": "Policy",
						"Key":   st.Name})
				delete(sMap, st.Name)
			}
		}
	}
	return err
}

func (r *RoutingPolicy) GetPolicyAssignment(id string, dir PolicyDirection) (RouteType, []*Policy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	rt := r.getDefaultPolicy(id, dir)
	l := make([]*Policy, 0)
	l = append(l, r.getPolicy(id, dir)...)
	return rt, l, nil
}

func (r *RoutingPolicy) AddPolicyAssignment(id string, dir PolicyDirection, policies []*config.PolicyDefinition, def RouteType) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ps := make([]*Policy, 0, len(policies))
	seen := make(map[string]bool)
	for _, x := range policies {
		p, ok := r.policyMap[x.Name]
		if !ok {
			err = fmt.Errorf("not found policy %s", x.Name)
			return
		}
		if seen[x.Name] {
			err = fmt.Errorf("duplicated policy %s", x.Name)
			return
		}
		seen[x.Name] = true
		ps = append(ps, p)
	}
	cur := r.getPolicy(id, dir)
	if cur == nil {
		err = r.setPolicy(id, dir, ps)
	} else {
		seen = make(map[string]bool)
		ps = append(cur, ps...)
		for _, x := range ps {
			if seen[x.Name] {
				err = fmt.Errorf("duplicated policy %s", x.Name)
				return
			}
			seen[x.Name] = true
		}
		err = r.setPolicy(id, dir, ps)
	}
	if err == nil && def != ROUTE_TYPE_NONE {
		err = r.setDefaultPolicy(id, dir, def)
	}
	return err
}

func (r *RoutingPolicy) DeletePolicyAssignment(id string, dir PolicyDirection, policies []*config.PolicyDefinition, all bool) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ps := make([]*Policy, 0, len(policies))
	seen := make(map[string]bool)
	for _, x := range policies {
		p, ok := r.policyMap[x.Name]
		if !ok {
			err = fmt.Errorf("not found policy %s", x.Name)
			return
		}
		if seen[x.Name] {
			err = fmt.Errorf("duplicated policy %s", x.Name)
			return
		}
		seen[x.Name] = true
		ps = append(ps, p)
	}
	cur := r.getPolicy(id, dir)

	if all {
		err = r.setPolicy(id, dir, nil)
		if err != nil {
			return
		}
		err = r.setDefaultPolicy(id, dir, ROUTE_TYPE_NONE)
	} else {
		l := len(cur) - len(ps)
		if l < 0 {
			// try to remove more than the assigned policies...
			l = len(cur)
		}
		n := make([]*Policy, 0, l)
		for _, y := range cur {
			found := false
			for _, x := range ps {
				if x.Name == y.Name {
					found = true
					break
				}
			}
			if !found {
				n = append(n, y)
			}
		}
		err = r.setPolicy(id, dir, n)
	}
	return err
}

func (r *RoutingPolicy) SetPolicyAssignment(id string, dir PolicyDirection, policies []*config.PolicyDefinition, def RouteType) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ps := make([]*Policy, 0, len(policies))
	seen := make(map[string]bool)
	for _, x := range policies {
		p, ok := r.policyMap[x.Name]
		if !ok {
			err = fmt.Errorf("not found policy %s", x.Name)
			return
		}
		if seen[x.Name] {
			err = fmt.Errorf("duplicated policy %s", x.Name)
			return
		}
		seen[x.Name] = true
		ps = append(ps, p)
	}
	r.getPolicy(id, dir)
	err = r.setPolicy(id, dir, ps)
	if err == nil && def != ROUTE_TYPE_NONE {
		err = r.setDefaultPolicy(id, dir, def)
	}
	return err
}

func (r *RoutingPolicy) Initialize() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.reload(config.RoutingPolicy{}); err != nil {
		r.logger.Error("failed to create routing policy",
			log.Fields{
				"Topic": "Policy",
				"Error": err})
		return err
	}
	return nil
}

func (r *RoutingPolicy) setPeerPolicy(id string, c config.ApplyPolicy) {
	for _, dir := range []PolicyDirection{POLICY_DIRECTION_IMPORT, POLICY_DIRECTION_EXPORT} {
		ps, def, err := r.getAssignmentFromConfig(dir, c)
		if err != nil {
			r.logger.Error("failed to get policy info",
				log.Fields{
					"Topic": "Policy",
					"Dir":   dir,
					"Error": err})
			continue
		}
		r.setDefaultPolicy(id, dir, def)
		r.setPolicy(id, dir, ps)
	}
}

func (r *RoutingPolicy) SetPeerPolicy(peerId string, c config.ApplyPolicy) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.setPeerPolicy(peerId, c)
	return nil
}

func (r *RoutingPolicy) Reset(rp *config.RoutingPolicy, ap map[string]config.ApplyPolicy) error {
	if rp == nil {
		return fmt.Errorf("routing Policy is nil in call to Reset")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.reload(*rp); err != nil {
		r.logger.Error("failed to create routing policy",
			log.Fields{
				"Topic": "Policy",
				"Error": err})
		return err
	}

	for id, c := range ap {
		r.setPeerPolicy(id, c)
	}
	return nil
}

func NewRoutingPolicy(logger log.Logger) *RoutingPolicy {
	return &RoutingPolicy{
		definedSetMap: make(map[DefinedType]map[string]DefinedSet),
		policyMap:     make(map[string]*Policy),
		statementMap:  make(map[string]*Statement),
		assignmentMap: make(map[string]*Assignment),
		logger:        logger,
	}
}

func CanImportToVrf(v *Vrf, path *Path) bool {
	f := func(arg []bgp.ExtendedCommunityInterface) []string {
		ret := make([]string, 0, len(arg))
		for _, a := range arg {
			ret = append(ret, fmt.Sprintf("RT:%s", a.String()))
		}
		return ret
	}
	set, _ := NewExtCommunitySet(config.ExtCommunitySet{
		ExtCommunitySetName: v.Name,
		ExtCommunityList:    f(v.ImportRt),
	})
	matchSet := config.MatchExtCommunitySet{
		ExtCommunitySet: v.Name,
		MatchSetOptions: config.MATCH_SET_OPTIONS_TYPE_ANY,
	}
	c, _ := NewExtCommunityCondition(matchSet)
	c.set = set
	return c.Evaluate(path, nil)
}

type PolicyAssignment struct {
	Name     string
	Type     PolicyDirection
	Policies []*Policy
	Default  RouteType
}

var _regexpMedActionType = regexp.MustCompile(`([+-]?)(\d+)`)

func toStatementApi(s *config.Statement) *api.Statement {
	cs := &api.Conditions{}
	o, _ := NewMatchOption(s.Conditions.MatchPrefixSet.MatchSetOptions)
	if s.Conditions.MatchPrefixSet.PrefixSet != "" {
		cs.PrefixSet = &api.MatchSet{
			Type: api.MatchSet_Type(o),
			Name: s.Conditions.MatchPrefixSet.PrefixSet,
		}
	}
	if s.Conditions.MatchNeighborSet.NeighborSet != "" {
		o, _ := NewMatchOption(s.Conditions.MatchNeighborSet.MatchSetOptions)
		cs.NeighborSet = &api.MatchSet{
			Type: api.MatchSet_Type(o),
			Name: s.Conditions.MatchNeighborSet.NeighborSet,
		}
	}
	if s.Conditions.BgpConditions.AsPathLength.Operator != "" {
		cs.AsPathLength = &api.AsPathLength{
			Length: s.Conditions.BgpConditions.AsPathLength.Value,
			Type:   api.AsPathLength_Type(s.Conditions.BgpConditions.AsPathLength.Operator.ToInt()),
		}
	}
	if s.Conditions.BgpConditions.MatchAsPathSet.AsPathSet != "" {
		cs.AsPathSet = &api.MatchSet{
			Type: api.MatchSet_Type(s.Conditions.BgpConditions.MatchAsPathSet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchAsPathSet.AsPathSet,
		}
	}
	if s.Conditions.BgpConditions.MatchCommunitySet.CommunitySet != "" {
		cs.CommunitySet = &api.MatchSet{
			Type: api.MatchSet_Type(s.Conditions.BgpConditions.MatchCommunitySet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchCommunitySet.CommunitySet,
		}
	}
	if s.Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet != "" {
		cs.ExtCommunitySet = &api.MatchSet{
			Type: api.MatchSet_Type(s.Conditions.BgpConditions.MatchExtCommunitySet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchExtCommunitySet.ExtCommunitySet,
		}
	}
	if s.Conditions.BgpConditions.MatchLargeCommunitySet.LargeCommunitySet != "" {
		cs.LargeCommunitySet = &api.MatchSet{
			Type: api.MatchSet_Type(s.Conditions.BgpConditions.MatchLargeCommunitySet.MatchSetOptions.ToInt()),
			Name: s.Conditions.BgpConditions.MatchLargeCommunitySet.LargeCommunitySet,
		}
	}
	if s.Conditions.BgpConditions.RouteType != "" {
		cs.RouteType = api.Conditions_RouteType(s.Conditions.BgpConditions.RouteType.ToInt())
	}
	if len(s.Conditions.BgpConditions.NextHopInList) > 0 {
		cs.NextHopInList = s.Conditions.BgpConditions.NextHopInList
	}
	if s.Conditions.BgpConditions.AfiSafiInList != nil {
		afiSafiIn := make([]*api.Family, 0)
		for _, afiSafiType := range s.Conditions.BgpConditions.AfiSafiInList {
			if mapped, ok := bgp.AddressFamilyValueMap[string(afiSafiType)]; ok {
				afi, safi := bgp.RouteFamilyToAfiSafi(mapped)
				afiSafiIn = append(afiSafiIn, &api.Family{Afi: api.Family_Afi(afi), Safi: api.Family_Safi(safi)})
			}
		}
		cs.AfiSafiIn = afiSafiIn
	}
	cs.RpkiResult = int32(s.Conditions.BgpConditions.RpkiValidationResult.ToInt())
	as := &api.Actions{
		RouteAction: func() api.RouteAction {
			switch s.Actions.RouteDisposition {
			case config.ROUTE_DISPOSITION_ACCEPT_ROUTE:
				return api.RouteAction_ACCEPT
			case config.ROUTE_DISPOSITION_REJECT_ROUTE:
				return api.RouteAction_REJECT
			}
			return api.RouteAction_NONE
		}(),
		Community: func() *api.CommunityAction {
			if len(s.Actions.BgpActions.SetCommunity.SetCommunityMethod.CommunitiesList) == 0 {
				return nil
			}
			return &api.CommunityAction{
				Type:        api.CommunityAction_Type(config.BgpSetCommunityOptionTypeToIntMap[config.BgpSetCommunityOptionType(s.Actions.BgpActions.SetCommunity.Options)]),
				Communities: s.Actions.BgpActions.SetCommunity.SetCommunityMethod.CommunitiesList}
		}(),
		Med: func() *api.MedAction {
			medStr := strings.TrimSpace(string(s.Actions.BgpActions.SetMed))
			if len(medStr) == 0 {
				return nil
			}
			matches := _regexpMedActionType.FindStringSubmatch(medStr)
			if len(matches) == 0 {
				return nil
			}
			action := api.MedAction_REPLACE
			switch matches[1] {
			case "+", "-":
				action = api.MedAction_MOD
			}
			value, err := strconv.ParseInt(matches[1]+matches[2], 10, 64)
			if err != nil {
				return nil
			}
			return &api.MedAction{
				Value: value,
				Type:  action,
			}
		}(),
		AsPrepend: func() *api.AsPrependAction {
			if len(s.Actions.BgpActions.SetAsPathPrepend.As) == 0 {
				return nil
			}
			var asn uint64
			useleft := false
			if s.Actions.BgpActions.SetAsPathPrepend.As != "last-as" {
				asn, _ = strconv.ParseUint(s.Actions.BgpActions.SetAsPathPrepend.As, 10, 32)
			} else {
				useleft = true
			}
			return &api.AsPrependAction{
				Asn:         uint32(asn),
				Repeat:      uint32(s.Actions.BgpActions.SetAsPathPrepend.RepeatN),
				UseLeftMost: useleft,
			}
		}(),
		ExtCommunity: func() *api.CommunityAction {
			if len(s.Actions.BgpActions.SetExtCommunity.SetExtCommunityMethod.CommunitiesList) == 0 {
				return nil
			}
			return &api.CommunityAction{
				Type:        api.CommunityAction_Type(config.BgpSetCommunityOptionTypeToIntMap[config.BgpSetCommunityOptionType(s.Actions.BgpActions.SetExtCommunity.Options)]),
				Communities: s.Actions.BgpActions.SetExtCommunity.SetExtCommunityMethod.CommunitiesList,
			}
		}(),
		LargeCommunity: func() *api.CommunityAction {
			if len(s.Actions.BgpActions.SetLargeCommunity.SetLargeCommunityMethod.CommunitiesList) == 0 {
				return nil
			}
			return &api.CommunityAction{
				Type:        api.CommunityAction_Type(config.BgpSetCommunityOptionTypeToIntMap[config.BgpSetCommunityOptionType(s.Actions.BgpActions.SetLargeCommunity.Options)]),
				Communities: s.Actions.BgpActions.SetLargeCommunity.SetLargeCommunityMethod.CommunitiesList,
			}
		}(),
		Nexthop: func() *api.NexthopAction {
			if len(string(s.Actions.BgpActions.SetNextHop)) == 0 {
				return nil
			}

			if string(s.Actions.BgpActions.SetNextHop) == "self" {
				return &api.NexthopAction{
					Self: true,
				}
			}
			if string(s.Actions.BgpActions.SetNextHop) == "unchanged" {
				return &api.NexthopAction{
					Unchanged: true,
				}
			}
			return &api.NexthopAction{
				Address: string(s.Actions.BgpActions.SetNextHop),
			}
		}(),
		LocalPref: func() *api.LocalPrefAction {
			if s.Actions.BgpActions.SetLocalPref == 0 {
				return nil
			}
			return &api.LocalPrefAction{Value: s.Actions.BgpActions.SetLocalPref}
		}(),
	}
	return &api.Statement{
		Name:       s.Name,
		Conditions: cs,
		Actions:    as,
	}
}

func NewAPIPolicyFromTableStruct(p *Policy) *api.Policy {
	return ToPolicyApi(p.ToConfig())
}

func ToPolicyApi(p *config.PolicyDefinition) *api.Policy {
	return &api.Policy{
		Name: p.Name,
		Statements: func() []*api.Statement {
			l := make([]*api.Statement, 0)
			for _, s := range p.Statements {
				l = append(l, toStatementApi(&s))
			}
			return l
		}(),
	}
}

func NewAPIPolicyAssignmentFromTableStruct(t *PolicyAssignment) *api.PolicyAssignment {
	return &api.PolicyAssignment{
		Direction: func() api.PolicyDirection {
			switch t.Type {
			case POLICY_DIRECTION_IMPORT:
				return api.PolicyDirection_IMPORT
			case POLICY_DIRECTION_EXPORT:
				return api.PolicyDirection_EXPORT
			}
			return api.PolicyDirection_UNKNOWN
		}(),
		DefaultAction: func() api.RouteAction {
			switch t.Default {
			case ROUTE_TYPE_ACCEPT:
				return api.RouteAction_ACCEPT
			case ROUTE_TYPE_REJECT:
				return api.RouteAction_REJECT
			}
			return api.RouteAction_NONE
		}(),
		Name: t.Name,
		Policies: func() []*api.Policy {
			l := make([]*api.Policy, 0)
			for _, p := range t.Policies {
				l = append(l, NewAPIPolicyFromTableStruct(p))
			}
			return l
		}(),
	}
}

func NewAPIRoutingPolicyFromConfigStruct(c *config.RoutingPolicy) (*api.RoutingPolicy, error) {
	definedSets, err := config.NewAPIDefinedSetsFromConfigStruct(&c.DefinedSets)
	if err != nil {
		return nil, err
	}
	policies := make([]*api.Policy, 0, len(c.PolicyDefinitions))
	for _, policy := range c.PolicyDefinitions {
		policies = append(policies, ToPolicyApi(&policy))
	}

	return &api.RoutingPolicy{
		DefinedSets: definedSets,
		Policies:    policies,
	}, nil
}
