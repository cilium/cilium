// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"encoding/binary"
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

var desiredRouteKeyBinaryVersion = 1

func (k DesiredRouteKey) MarshalBinary() ([]byte, error) {
	var (
		buf []byte
		tmp [4]byte
	)

	buf = append(buf, byte(desiredRouteKeyBinaryVersion))

	binary.LittleEndian.PutUint32(tmp[:], uint32(k.Table))
	buf = append(buf, tmp[:]...)

	addrBuf, err := k.Prefix.Addr().MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf = append(buf, byte(len(addrBuf)))
	buf = append(buf, addrBuf...)
	buf = append(buf, byte(k.Prefix.Bits()))

	binary.LittleEndian.PutUint32(tmp[:], k.Priority)
	buf = append(buf, tmp[:]...)

	return buf, nil
}

func (k *DesiredRouteKey) UnmarshalBinary(data []byte) error {
	if len(data) < 10 { // Minimum length: 1 (version) + 4 (table) + 1 (addr len) + 4 (priority)
		return fmt.Errorf("data too short to unmarshal DesiredRouteKey")
	}

	if data[0] != byte(desiredRouteKeyBinaryVersion) {
		return fmt.Errorf("unsupported DesiredRouteKey version: %d", data[0])
	}
	data = data[1:]

	k.Table = TableID(binary.LittleEndian.Uint32(data[0:4]))
	data = data[4:]

	addrLen := int(data[0])
	data = data[1:]
	if len(data) < addrLen+1+4 { // addr + 1 (prefix bits) + 4 (priority)
		return fmt.Errorf("data too short to unmarshal DesiredRouteKey")
	}
	addr, ok := netip.AddrFromSlice(data[0:addrLen])
	if !ok {
		return fmt.Errorf("failed to unmarshal IP address")
	}
	prefixBits := int(data[addrLen])
	k.Prefix = netip.PrefixFrom(addr, prefixBits)
	data = data[addrLen+1:]

	k.Priority = binary.LittleEndian.Uint32(data[0:4])

	return nil
}

type NexthopInfo struct {
	Device  *tables.Device
	Nexthop netip.Addr
}

func (nh *NexthopInfo) String() string {
	if nh == nil {
		return "none"
	}
	parts := []string{}
	if nh.Nexthop.IsValid() {
		parts = append(parts, nh.Nexthop.String())
	}
	if nh.Device != nil {
		parts = append(parts, nh.Device.Name+" ("+strconv.Itoa(nh.Device.Index)+")")
	}
	return strings.Join(parts, " ")
}

type MultiPathInfo []*NexthopInfo

func (m MultiPathInfo) String() string {
	if len(m) == 0 {
		return "none"
	}
	var nhs []string
	for _, nh := range m {
		nhs = append(nhs, nh.String())
	}
	return "[" + strings.Join(nhs, ", ") + "]"
}

type DesiredRoute struct {
	// Composite primary key for the route.
	Owner    *RouteOwner
	Table    TableID
	Prefix   netip.Prefix
	Priority uint32

	// The administrative distance of the route, lower values are preferred.
	AdminDistance AdminDistance
	// If true, the route is selected for installation, a calculated property.
	selected bool

	// Optional, if [netip.Addr.IsValid] then nexthop is specified.
	Nexthop netip.Addr
	// Optional, if [netip.Addr.IsValid] then source address is specified.
	Src netip.Addr
	// Optional, non-nil if device is specified.
	Device *tables.Device
	// Optional, if it's empty, no multipath is specified. This is mutually
	// exclusive with Nexthop and Device.
	MultiPath MultiPathInfo
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
		"AD",
		"Selected",
		"Nexthop",
		"Src",
		"Device",
		"MultiPath",
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

	row = append(row, strconv.FormatUint(uint64(dr.AdminDistance), 10))
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

	row = append(row, dr.MultiPath.String())

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
	ndr := dr.Clone()
	ndr.status = s
	return ndr
}

func (dr *DesiredRoute) Clone() *DesiredRoute {
	dr2 := *dr
	return &dr2
}

func (dr *DesiredRoute) ValidateAndSetDefaults() error {
	if dr.Owner == nil {
		return fmt.Errorf("route must have an owner")
	}

	if !dr.Prefix.Addr().IsValid() {
		return fmt.Errorf("route must have a valid prefix")
	}

	if dr.AdminDistance == 0 {
		return fmt.Errorf("route must have a non-zero admin distance")
	}

	// When not specified, the route should be added to the main table.
	if dr.Table == 0 {
		dr.Table = TableMain
	}

	return nil
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
	return statedb.NewTable(
		db,
		"desired-routes",
		DesiredRouteIndex,
		DesiredRouteTablePrefixIndex,
		DesiredRouteTableDeviceIndex,
	)
}
