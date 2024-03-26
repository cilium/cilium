// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"net/netip"
	"strings"

	"github.com/cilium/cilium/pkg/container"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/cilium/cilium/pkg/statedb/index"
	"github.com/cilium/cilium/pkg/statedb/reconciler"
)

const IPSetTableName = "ipset"

type AddrSet = container.ImmSet[netip.Addr]

func NewAddrSet(addrs ...netip.Addr) AddrSet {
	return container.NewImmSetFunc(
		netip.Addr.Compare,
		addrs...,
	)
}

var (
	IPSetNameIndex = statedb.Index[*IPSet, string]{
		Name: "name",
		FromObject: func(s *IPSet) index.KeySet {
			return index.NewKeySet(index.String(s.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}
)

func NewIPSetTable(db *statedb.DB) (statedb.RWTable[*IPSet], error) {
	tbl, err := statedb.NewTable(
		IPSetTableName,
		IPSetNameIndex,
	)
	return tbl, err
}

func (s *IPSet) TableHeader() []string {
	return []string{"Name", "Family", "Addrs", "Status"}
}

func (s *IPSet) TableRow() []string {
	ss := make([]string, 0, s.Addrs.Len())
	for _, addr := range s.Addrs.AsSlice() {
		ss = append(ss, addr.String())
	}
	return []string{s.Name, s.Family, strings.Join(ss, ","), s.Status.String()}
}

type IPSet struct {
	Name   string
	Family string
	Addrs  AddrSet

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
	return &IPSet{
		Name:   s.Name,
		Family: s.Family,
		Addrs:  s.Addrs.Insert(addrs...),
		Status: s.Status,
	}
}

func (s *IPSet) WithoutAddrs(addrs ...netip.Addr) *IPSet {
	return &IPSet{
		Name:   s.Name,
		Family: s.Family,
		Addrs:  s.Addrs.Delete(addrs...),
		Status: s.Status,
	}
}
