// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"net/netip"
	"strings"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

var (
	IPSetNameIndex = statedb.Index[*IPSet, string]{
		Name: "name",
		FromObject: func(s *IPSet) index.KeySet {
			return index.NewKeySet(index.String(s.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}

	IPSetTableName = "ipset"
)

func NewIPSetTable(db *statedb.DB) (statedb.RWTable[*IPSet], error) {
	tbl, err := statedb.NewTable[*IPSet](
		IPSetTableName,
		IPSetNameIndex,
	)
	return tbl, err
}

func (s *IPSet) TableHeader() []string {
	return []string{"Name", "Family", "Addrs", "Status"}
}

func (s *IPSet) TableRow() []string {
	ss := make([]string, 0, len(s.Addrs))
	for addr := range s.Addrs {
		ss = append(ss, addr.String())
	}
	return []string{s.Name, s.Family, strings.Join(ss, ","), s.Status.String()}
}

type IPSet struct {
	Name   string
	Family string
	Addrs  sets.Set[netip.Addr]

	Status reconciler.Status
}

func (s *IPSet) GetStatus() reconciler.Status {
	return s.Status
}

func (s *IPSet) WithStatus(newStatus reconciler.Status) *IPSet {
	return &IPSet{
		Name:   s.Name,
		Family: s.Family,
		Addrs:  s.Addrs,
		Status: newStatus,
	}
}

func (s *IPSet) WithAddrs(addrs ...netip.Addr) *IPSet {
	s2 := &IPSet{
		Name:   s.Name,
		Family: s.Family,
		Addrs:  s.Addrs.Clone(),
		Status: s.Status,
	}
	s2.Addrs.Insert(addrs...)
	return s2
}

func (s *IPSet) WithoutAddrs(addrs ...netip.Addr) *IPSet {
	s2 := &IPSet{
		Name:   s.Name,
		Family: s.Family,
		Addrs:  s.Addrs.Clone(),
		Status: s.Status,
	}
	s2.Addrs.Delete(addrs...)
	return s2
}
