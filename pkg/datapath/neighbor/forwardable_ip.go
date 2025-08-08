// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package neighbor

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"go.yaml.in/yaml/v3"
)

var _ statedb.TableWritable = &ForwardableIP{}

type ForwardableIPOwnerType int

const (
	ForwardableIPOwnerNode ForwardableIPOwnerType = iota
	ForwardableIPOwnerService
)

func (fip ForwardableIPOwnerType) String() string {
	switch fip {
	case ForwardableIPOwnerNode:
		return "node"
	case ForwardableIPOwnerService:
		return "service"
	default:
		return "unknown"
	}
}

func (fip *ForwardableIPOwnerType) UnmarshalYAML(unmarshal *yaml.Node) (err error) {
	*fip, err = forwardableIPOwnerTypeFromString(unmarshal.Value)
	return err
}

func forwardableIPOwnerTypeFromString(s string) (ForwardableIPOwnerType, error) {
	switch s {
	case "node":
		return ForwardableIPOwnerNode, nil
	case "service":
		return ForwardableIPOwnerService, nil
	default:
		return 0, fmt.Errorf("invalid ForwardableIPOwnerType: %s", s)
	}
}

type ForwardableIPOwner struct {
	Type ForwardableIPOwnerType
	ID   string
}

func (fip ForwardableIPOwner) String() string {
	return fmt.Sprintf("%s:%s", fip.Type, fip.ID)
}

type ForwardableIP struct {
	IP     netip.Addr
	Owners []ForwardableIPOwner
}

func (fip *ForwardableIP) TableHeader() []string {
	return []string{"IP", "Owners"}
}

func (fip *ForwardableIP) TableRow() []string {
	ownerStrings := make([]string, 0, len(fip.Owners))
	for _, owner := range fip.Owners {
		ownerStrings = append(ownerStrings, owner.String())
	}

	return []string{
		fip.IP.String(),
		strings.Join(ownerStrings, ", "),
	}
}

var (
	ForwardableIPIndex = statedb.Index[*ForwardableIP, netip.Addr]{
		Name: "id",
		FromObject: func(d *ForwardableIP) index.KeySet {
			return index.NewKeySet(index.NetIPAddr(d.IP))
		},
		FromKey:    index.NetIPAddr,
		FromString: index.NetIPAddrString,
		Unique:     true,
	}
)

// Return the read-only table for consumption, and the [ForwardableIPManager] for modification.
func newForwardableIPTable(db *statedb.DB, config *CommonConfig) (*ForwardableIPManager, statedb.Table[*ForwardableIP], error) {
	tbl, err := statedb.NewTable(
		db,
		"forwardable-ip",
		ForwardableIPIndex,
	)
	if err != nil {
		return nil, nil, err
	}

	return &ForwardableIPManager{
			db:     db,
			table:  tbl,
			config: config,
		},
		tbl, nil
}

// ForwardableIPManager manages modification of the ForwardableIP table.
// It abstracts away the logic that tracks multiple owners of the same IP.
type ForwardableIPManager struct {
	db     *statedb.DB
	table  statedb.RWTable[*ForwardableIP]
	config *CommonConfig
}

type ForwardableIPInitializer struct {
	initializer func(statedb.WriteTxn)
}

// RegisterInitializer registers an initializer for the ForwardableIP table. This has to be done
// during the hive construction phase. An initializer will guarantee that the forwardable IP table
// is not considered "initialized" until the initializer is finished.
func (fim *ForwardableIPManager) RegisterInitializer(name string) ForwardableIPInitializer {
	if !fim.config.Enabled {
		return ForwardableIPInitializer{
			initializer: func(statedb.WriteTxn) {},
		}
	}

	tx := fim.db.WriteTxn(fim.table)
	defer tx.Commit()

	return ForwardableIPInitializer{
		initializer: fim.table.RegisterInitializer(tx, name),
	}
}

// Mark an initializer as finished.
func (fim *ForwardableIPManager) FinishInitializer(initializer ForwardableIPInitializer) {
	if !fim.config.Enabled {
		return
	}

	tx := fim.db.WriteTxn(fim.table)
	defer tx.Commit()

	initializer.initializer(tx)
}

// Insert a forwardable IP into the table for a given owner.
// If the IP already exists, the owner is added to the existing entry.
func (fim *ForwardableIPManager) Insert(ip netip.Addr, owner ForwardableIPOwner) error {
	if !fim.config.Enabled {
		return fmt.Errorf("L2 neighbor discovery is not enabled")
	}

	fi := &ForwardableIP{
		IP:     ip,
		Owners: []ForwardableIPOwner{owner},
	}

	tx := fim.db.WriteTxn(fim.table)
	defer tx.Abort()

	_, _, err := fim.table.Modify(tx, fi, func(old *ForwardableIP, new *ForwardableIP) *ForwardableIP {
		idx := slices.Index(old.Owners, owner)
		if idx == -1 {
			new.Owners = append(slices.Clone(old.Owners), owner)
		}
		return new
	})
	if err != nil {
		return err
	}

	tx.Commit()
	return nil
}

// Delete removes and IP from the table for a given owner. If an IP has multiple owners,
// the given owner is removed from the list of owners. If the last owner is removed,
// the IP is deleted from the table.
func (fim *ForwardableIPManager) Delete(ip netip.Addr, owner ForwardableIPOwner) error {
	if !fim.config.Enabled {
		return fmt.Errorf("L2 neighbor discovery is not enabled")
	}

	tx := fim.db.WriteTxn(fim.table)
	defer tx.Abort()

	fi, _, found := fim.table.Get(tx, ForwardableIPIndex.Query(ip))
	if !found {
		return nil
	}

	owners := slices.Clone(fi.Owners)
	if idx := slices.Index(owners, owner); idx != -1 {
		owners = slices.Delete(owners, idx, idx+1)
	}
	if len(owners) == 0 {
		_, _, err := fim.table.Delete(tx, fi)
		if err != nil {
			return err
		}

		tx.Commit()

		return nil
	}

	newFi := &ForwardableIP{
		IP:     fi.IP,
		Owners: owners,
	}
	_, _, err := fim.table.Insert(tx, newFi)
	if err != nil {
		return err
	}

	tx.Commit()

	return nil
}

func (fim *ForwardableIPManager) Enabled() bool {
	return fim.config.Enabled
}
