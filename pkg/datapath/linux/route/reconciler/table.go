// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

var _ statedb.TableWritable = &DesiredRoute{}

type DesiredRouteKey struct {
	Owner    *RouteOwner
	Table    TableID
	Prefix   netip.Prefix
	Priority uint32
}

func (k DesiredRouteKey) Key() index.Key {
	var key []byte
	if k.Owner != nil {
		key = index.String(k.Owner.name)
		// Owner name is variable, insert a 0x00 byte to separate it from the rest of the key.
		key = append(key, 0x00)
	}

	if k.Table != 0 {
		key = append(key, index.Uint32(uint32(k.Table))...)
	}

	if k.Prefix.IsValid() {
		key = append(key, index.NetIPAddr(k.Prefix.Addr())...)
		key = append(key, uint8(k.Prefix.Bits()))
	}

	if k.Priority != 0 {
		key = append(key, index.Uint32(k.Priority)...)
	}

	return key
}

func (k DesiredRouteKey) String() string {
	parts := []string{k.Owner.String(), k.Table.String(), k.Prefix.String()}
	if k.Priority != 0 {
		parts = append(parts, strconv.FormatUint(uint64(k.Priority), 10))
	}
	return strings.Join(parts, ":")
}

type DesiredRoute struct {
	// Composite primary key for the route.
	Owner    *RouteOwner
	Table    TableID
	Prefix   netip.Prefix
	Priority uint32

	// If true, the route is selected for installation, a calculated property.
	selected bool

	// Optional, if [netip.Addr.IsValid] then nexthop is specified.
	Nexthop netip.Addr
	// Optional, if [netip.Addr.IsValid] then source address is specified.
	Src netip.Addr
	// Optional, non-nil if device is specified.
	Device *tables.Device
	// Optional, if 0 no MTU is specified.
	MTU uint32
	// Optional, if 0 no scope is specified.
	Scope Scope
	// Optional, if 0 no type is specified.
	Type Type

	status reconciler.Status
}

func (dr *DesiredRoute) GetFullKey() DesiredRouteKey {
	return DesiredRouteKey{
		Owner:    dr.Owner,
		Table:    dr.Table,
		Prefix:   dr.Prefix,
		Priority: dr.Priority,
	}
}

func (dr *DesiredRoute) GetOwnerlessKey() DesiredRouteKey {
	return DesiredRouteKey{
		Table:    dr.Table,
		Prefix:   dr.Prefix,
		Priority: dr.Priority,
	}
}

func (dr *DesiredRoute) TableHeader() []string {
	return []string{
		"Owner",
		"Table",
		"Prefix",
		"Priority",
		"Selected",
		"Nexthop",
		"Src",
		"Device",
		"MTU",
		"Scope",
		"Type",
		"Status",
	}
}

func (dr *DesiredRoute) TableRow() []string {
	row := []string{
		dr.Owner.String(),
		dr.Table.String(),
		dr.Prefix.String(),
	}

	if dr.Priority == 0 {
		row = append(row, "none")
	} else {
		row = append(row, strconv.FormatUint(uint64(dr.Priority), 10))
	}

	row = append(row, strconv.FormatBool(dr.selected))

	if !dr.Nexthop.IsValid() {
		row = append(row, "none")
	} else {
		row = append(row, dr.Nexthop.String())
	}

	if !dr.Src.IsValid() {
		row = append(row, "none")
	} else {
		row = append(row, dr.Src.String())
	}

	if dr.Device == nil {
		row = append(row, "none")
	} else {
		row = append(row, dr.Device.Name+" ("+strconv.Itoa(dr.Device.Index)+")")
	}

	if dr.MTU == 0 {
		row = append(row, "none")
	} else {
		row = append(row, strconv.FormatUint(uint64(dr.MTU), 10))
	}

	row = append(row, dr.Scope.String())
	row = append(row, dr.Type.String())
	row = append(row, dr.status.String())

	return row
}

func (dr *DesiredRoute) GetStatus() reconciler.Status {
	return dr.status
}

func (dr *DesiredRoute) SetStatus(s reconciler.Status) *DesiredRoute {
	dr.status = s
	return dr
}

func (dr *DesiredRoute) Clone() *DesiredRoute {
	dr2 := *dr
	return &dr2
}

var (
	DesiredRouteIndex = statedb.Index[*DesiredRoute, DesiredRouteKey]{
		Name: "id",
		FromObject: func(d *DesiredRoute) index.KeySet {
			return index.NewKeySet(d.GetFullKey().Key())
		},
		FromKey: DesiredRouteKey.Key,
		FromString: func(s string) (index.Key, error) {
			parts := strings.Split(s, ":")
			if len(parts) > 3 {
				return nil, fmt.Errorf("bad key, expected \"owner[:table[:prefix[:priority]]]\", got %s", s)
			}

			var key DesiredRouteKey
			if len(parts) >= 2 {
				if err := key.Table.FromString(parts[1]); err != nil {
					return nil, fmt.Errorf("bad key, expected \"owner[:table[:prefix[:priority]]]\", got %s: %w", s, err)
				}
			}

			if len(parts) >= 3 {
				var err error
				key.Prefix, err = netip.ParsePrefix(parts[2])
				if err != nil {
					return nil, fmt.Errorf("bad key, expected \"owner[:table[:prefix[:priority]]]\", got %s: %w", s, err)
				}
			}

			if len(parts) >= 4 {
				prio, err := strconv.ParseUint(parts[3], 10, 32)
				if err != nil {
					return nil, fmt.Errorf("bad key, expected \"owner[:table[:prefix[:priority]]]\", got %s: %w", s, err)
				}
				key.Priority = uint32(prio)
			}

			return key.Key(), nil
		},
		Unique: true,
	}

	DesiredRouteTablePrefixIndex = statedb.Index[*DesiredRoute, DesiredRouteKey]{
		Name: "table-prefix",
		FromObject: func(d *DesiredRoute) index.KeySet {
			return index.NewKeySet(d.GetOwnerlessKey().Key())
		},
		FromKey: func(key DesiredRouteKey) index.Key {
			key.Owner = nil // Owner is not part of the key for this index
			return key.Key()
		},
		FromString: func(s string) (index.Key, error) {
			// The string is expected to be in the format "table:prefix[:priority]"
			parts := strings.Split(s, ":")

			var key DesiredRouteKey
			if err := key.Table.FromString(parts[0]); err != nil {
				return nil, fmt.Errorf("bad key, expected \"table:prefix:priority\", got %s: %w", s, err)
			}

			if len(parts) < 2 {
				return key.Key(), nil
			}

			var err error
			key.Prefix, err = netip.ParsePrefix(parts[1])
			if err != nil {
				return nil, err
			}

			if len(parts) < 3 {
				return key.Key(), nil
			}

			prio, err := strconv.ParseUint(parts[2], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("bad key, expected \"table:prefix:priority\", got %s: %w", s, err)
			}
			key.Priority = uint32(prio)

			return key.Key(), nil
		},
		Unique: false,
	}

	DesiredRouteTableDeviceIndex = statedb.Index[*DesiredRoute, int]{
		Name: "device",
		FromObject: func(obj *DesiredRoute) index.KeySet {
			if obj.Device == nil {
				return index.NewKeySet()
			}
			return index.NewKeySet(index.Int(obj.Device.Index))
		},
		FromKey: func(key int) index.Key {
			return index.Int(key)
		},
		Unique: false,
	}
)

func newDesiredRouteTable(db *statedb.DB) (statedb.RWTable[*DesiredRoute], error) {
	tbl, err := statedb.NewTable(
		"desired-routes",
		DesiredRouteIndex,
		DesiredRouteTablePrefixIndex,
		DesiredRouteTableDeviceIndex,
	)
	if err != nil {
		return nil, err
	}

	return tbl, db.RegisterTable(tbl)
}
