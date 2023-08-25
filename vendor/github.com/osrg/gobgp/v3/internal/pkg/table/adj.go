// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
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
	"fmt"

	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

type AdjRib struct {
	accepted map[bgp.RouteFamily]int
	table    map[bgp.RouteFamily]*Table
	logger   log.Logger
}

func NewAdjRib(logger log.Logger, rfList []bgp.RouteFamily) *AdjRib {
	m := make(map[bgp.RouteFamily]*Table)
	for _, f := range rfList {
		m[f] = NewTable(logger, f)
	}
	return &AdjRib{
		table:    m,
		accepted: make(map[bgp.RouteFamily]int),
		logger:   logger,
	}
}

func (adj *AdjRib) Update(pathList []*Path) {
	for _, path := range pathList {
		if path == nil || path.IsEOR() {
			continue
		}
		rf := path.GetRouteFamily()
		t := adj.table[path.GetRouteFamily()]
		d := t.getOrCreateDest(path.GetNlri(), 0)
		var old *Path
		idx := -1
		for i, p := range d.knownPathList {
			if p.GetNlri().PathIdentifier() == path.GetNlri().PathIdentifier() {
				idx = i
				break
			}
		}
		if idx != -1 {
			old = d.knownPathList[idx]
		}

		if path.IsWithdraw {
			if idx != -1 {
				d.knownPathList = append(d.knownPathList[:idx], d.knownPathList[idx+1:]...)
				if len(d.knownPathList) == 0 {
					t.deleteDest(d)
				}
				if !old.IsRejected() {
					adj.accepted[rf]--
				}
			}
			path.SetDropped(true)
		} else {
			if idx != -1 {
				if old.IsRejected() && !path.IsRejected() {
					adj.accepted[rf]++
				} else if !old.IsRejected() && path.IsRejected() {
					adj.accepted[rf]--
				}
				if old.Equal(path) {
					path.setTimestamp(old.GetTimestamp())
				}
				d.knownPathList[idx] = path
			} else {
				d.knownPathList = append(d.knownPathList, path)
				if !path.IsRejected() {
					adj.accepted[rf]++
				}
			}
		}
	}
}

/*
The provided pathList is expected to be the real candidate routes after policy evaluation.

	For routes that are filtered by policy, there could be a mismatch between display
	and actual rib sent to the peer (if softreset out was not run).
	Only used to display adj-out because we do not maintain a separate adj-out table
*/
func (adj *AdjRib) UpdateAdjRibOut(pathList []*Path) {
	for _, path := range pathList {
		if path == nil || path.IsEOR() {
			continue
		}
		t := adj.table[path.GetRouteFamily()]
		d := t.getOrCreateDest(path.GetNlri(), 0)
		d.knownPathList = append(d.knownPathList, path)
	}
}

func (adj *AdjRib) walk(families []bgp.RouteFamily, fn func(*Destination) bool) {
	for _, f := range families {
		if t, ok := adj.table[f]; ok {
			for _, d := range t.destinations {
				if fn(d) {
					return
				}
			}
		}
	}
}

func (adj *AdjRib) PathList(rfList []bgp.RouteFamily, accepted bool) []*Path {
	pathList := make([]*Path, 0, adj.Count(rfList))
	adj.walk(rfList, func(d *Destination) bool {
		for _, p := range d.knownPathList {
			if accepted && p.IsRejected() {
				continue
			}
			pathList = append(pathList, p)
		}
		return false
	})
	return pathList
}

func (adj *AdjRib) Count(rfList []bgp.RouteFamily) int {
	count := 0
	adj.walk(rfList, func(d *Destination) bool {
		count += len(d.knownPathList)
		return false
	})
	return count
}

func (adj *AdjRib) Accepted(rfList []bgp.RouteFamily) int {
	count := 0
	for _, rf := range rfList {
		if n, ok := adj.accepted[rf]; ok {
			count += n
		}
	}
	return count
}

func (adj *AdjRib) Drop(rfList []bgp.RouteFamily) []*Path {
	l := make([]*Path, 0, adj.Count(rfList))
	adj.walk(rfList, func(d *Destination) bool {
		for _, p := range d.knownPathList {
			w := p.Clone(true)
			w.SetDropped(true)
			l = append(l, w)
		}
		return false
	})
	for _, rf := range rfList {
		adj.table[rf] = NewTable(adj.logger, rf)
		adj.accepted[rf] = 0
	}
	return l
}

func (adj *AdjRib) DropStale(rfList []bgp.RouteFamily) []*Path {
	pathList := make([]*Path, 0, adj.Count(rfList))
	adj.walk(rfList, func(d *Destination) bool {
		for _, p := range d.knownPathList {
			if p.IsStale() {
				w := p.Clone(true)
				w.SetDropped(true)
				pathList = append(pathList, w)
			}
		}
		return false
	})
	adj.Update(pathList)
	return pathList
}

func (adj *AdjRib) StaleAll(rfList []bgp.RouteFamily) []*Path {
	pathList := make([]*Path, 0, adj.Count(rfList))
	adj.walk(rfList, func(d *Destination) bool {
		for i, p := range d.knownPathList {
			n := p.Clone(false)
			n.MarkStale(true)
			n.SetRejected(p.IsRejected())
			d.knownPathList[i] = n
			if !n.IsRejected() {
				pathList = append(pathList, n)
			}
		}
		return false
	})
	return pathList
}

func (adj *AdjRib) MarkLLGRStaleOrDrop(rfList []bgp.RouteFamily) []*Path {
	pathList := make([]*Path, 0, adj.Count(rfList))
	adj.walk(rfList, func(d *Destination) bool {
		for i, p := range d.knownPathList {
			if p.HasNoLLGR() {
				n := p.Clone(true)
				n.SetDropped(true)
				pathList = append(pathList, n)
			} else {
				n := p.Clone(false)
				n.SetRejected(p.IsRejected())
				n.SetCommunities([]uint32{uint32(bgp.COMMUNITY_LLGR_STALE)}, false)
				if p.IsRejected() {
					d.knownPathList[i] = n
				} else {
					pathList = append(pathList, n)
				}
			}
		}
		return false
	})
	adj.Update(pathList)
	return pathList
}

func (adj *AdjRib) Select(family bgp.RouteFamily, accepted bool, option ...TableSelectOption) (*Table, error) {
	t, ok := adj.table[family]
	if !ok {
		t = NewTable(adj.logger, family)
	}
	option = append(option, TableSelectOption{adj: true})
	return t.Select(option...)
}

func (adj *AdjRib) TableInfo(family bgp.RouteFamily) (*TableInfo, error) {
	if _, ok := adj.table[family]; !ok {
		return nil, fmt.Errorf("%s unsupported", family)
	}
	c := adj.Count([]bgp.RouteFamily{family})
	a := adj.Accepted([]bgp.RouteFamily{family})
	return &TableInfo{
		NumDestination: c,
		NumPath:        c,
		NumAccepted:    a,
	}, nil
}
