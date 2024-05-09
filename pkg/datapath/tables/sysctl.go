// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
)

var (
	SysctlNameIndex = statedb.Index[*Sysctl, string]{
		Name: "name",
		FromObject: func(s *Sysctl) index.KeySet {
			return index.NewKeySet(index.String(s.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}

	SysctlStatusIndex = reconciler.NewStatusIndex((*Sysctl).GetStatus)

	SysctlTableName = "sysctl"
)

func NewSysctlTable(db *statedb.DB) (statedb.RWTable[*Sysctl], statedb.Index[*Sysctl, reconciler.StatusKind], error) {
	tbl, err := statedb.NewTable(
		SysctlTableName,
		SysctlNameIndex,
		SysctlStatusIndex,
	)
	return tbl, SysctlStatusIndex, err
}

func (*Sysctl) TableHeader() []string {
	return []string{"Name", "Value", "Status"}
}

func (s *Sysctl) TableRow() []string {
	return []string{s.Name, s.Val, s.Status.String()}
}

// Sysctl is the representation of a kernel sysctl parameter.
type Sysctl struct {
	Name      string
	Val       string
	IgnoreErr bool

	// Warn if non-empty is the alternative warning log message to use when IgnoreErr is false.
	Warn string

	Status reconciler.Status
}

func (s *Sysctl) Clone() *Sysctl {
	s2 := *s
	return &s2
}

func (s *Sysctl) GetStatus() reconciler.Status {
	return s.Status
}

func (s *Sysctl) SetStatus(newStatus reconciler.Status) *Sysctl {
	s.Status = newStatus
	return s
}
