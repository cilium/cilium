// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighbor

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"
)

type DesiredNeighbor struct {
	DesiredNeighborKey

	Status reconciler.Status
}

func (dn *DesiredNeighbor) Clone() *DesiredNeighbor {
	return &DesiredNeighbor{
		DesiredNeighborKey: dn.DesiredNeighborKey,
		Status:             dn.Status,
	}
}

func (dn *DesiredNeighbor) SetStatus(status reconciler.Status) *DesiredNeighbor {
	n := dn.Clone()
	n.Status = status
	return n
}

func (dn *DesiredNeighbor) GetStatus() reconciler.Status {
	return dn.Status
}

type DesiredNeighborKey struct {
	IP      netip.Addr
	IfIndex int
}

func (dn DesiredNeighborKey) TableKey() index.Key {
	return append(index.Int(dn.IfIndex), index.NetIPAddr(dn.IP)...)
}

func (dn *DesiredNeighborKey) String() string {
	return fmt.Sprintf("%s@%d", dn.IP.String(), dn.IfIndex)
}

func desiredNeighborKeyFromString(s string) (index.Key, error) {
	ipStr, ifIndexStr, ok := strings.Cut(s, "@")
	if !ok {
		return nil, fmt.Errorf("invalid key format: '%s' expected {ip}@{ifindex}", s)
	}

	ip, err := index.NetIPAddrString(ipStr)
	if err != nil {
		return nil, fmt.Errorf("invalid IP address: %w", err)
	}

	ifIndex, err := index.IntString(ifIndexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid interface index: %w", err)
	}

	return append(ifIndex, ip...), nil
}

func (dn *DesiredNeighbor) TableHeader() []string {
	return []string{
		"IP",
		"Link",
		"Status",
	}
}

func (dn *DesiredNeighbor) TableRow() []string {
	return []string{
		dn.IP.String(),
		fmt.Sprintf("%d", dn.IfIndex),
		dn.Status.Kind.String(),
	}
}

var (
	DesiredNeighborIndex = statedb.Index[*DesiredNeighbor, DesiredNeighborKey]{
		Name: "id",
		FromObject: func(d *DesiredNeighbor) index.KeySet {
			return index.NewKeySet(d.TableKey())
		},
		FromKey:    DesiredNeighborKey.TableKey,
		FromString: desiredNeighborKeyFromString,
		Unique:     true,
	}
)

func newDesiredNeighborTable(db *statedb.DB) (statedb.RWTable[*DesiredNeighbor], error) {
	return statedb.NewTable(
		db,
		"desired-neighbors",
		DesiredNeighborIndex,
	)
}
