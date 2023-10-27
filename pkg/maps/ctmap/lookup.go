// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"fmt"
	"net/netip"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/u8proto"
)

func createTupleKey(isGlobal bool, srcAddr, dstAddr string, proto u8proto.U8proto, ingress bool) (bpf.MapKey, bool, error) {
	srcAddrPort, err := netip.ParseAddrPort(srcAddr)
	if err != nil {
		return nil, false, fmt.Errorf("invalid source address '%s': %s", srcAddr, err)
	}

	dstAddrPort, err := netip.ParseAddrPort(dstAddr)
	if err != nil {
		return nil, false, fmt.Errorf("invalid destination address '%s': %s", dstAddr, err)
	}

	if srcAddrPort.Addr().Is4() {
		if isGlobal {
			key := &CtKey4Global{
				TupleKey4Global: tuple.TupleKey4Global{
					TupleKey4: tuple.TupleKey4{
						SourcePort: uint16(srcAddrPort.Port()),
						DestPort:   uint16(dstAddrPort.Port()),
						NextHeader: proto,
						Flags:      TUPLE_F_OUT,
					},
				},
			}
			// CTmap has the addresses in the reverse order w.r.t. the original direction
			key.SourceAddr.FromAddr(dstAddrPort.Addr())
			key.DestAddr.FromAddr(srcAddrPort.Addr())
			if ingress {
				key.Flags = TUPLE_F_IN
			}
			return key.ToNetwork(), true, nil
		}

		key := &CtKey4{
			TupleKey4: tuple.TupleKey4{
				SourcePort: uint16(srcAddrPort.Port()),
				DestPort:   uint16(dstAddrPort.Port()),
				NextHeader: proto,
				Flags:      TUPLE_F_OUT,
			},
		}
		// CTmap has the addresses in the reverse order w.r.t. the original direction
		key.SourceAddr.FromAddr(dstAddrPort.Addr())
		key.DestAddr.FromAddr(srcAddrPort.Addr())
		if ingress {
			key.Flags = TUPLE_F_IN
		}
		return key.ToNetwork(), true, nil
	}

	if isGlobal {
		key := &CtKey6Global{
			TupleKey6Global: tuple.TupleKey6Global{
				TupleKey6: tuple.TupleKey6{
					SourcePort: uint16(srcAddrPort.Port()),
					DestPort:   uint16(dstAddrPort.Port()),
					NextHeader: proto,
					Flags:      TUPLE_F_OUT,
				},
			},
		}
		// CTmap has the addresses in the reverse order w.r.t. the original direction
		key.SourceAddr.FromAddr(dstAddrPort.Addr())
		key.DestAddr.FromAddr(srcAddrPort.Addr())
		if ingress {
			key.Flags = TUPLE_F_IN
		}
		return key.ToNetwork(), false, nil
	}

	key := &CtKey6{
		TupleKey6: tuple.TupleKey6{
			SourcePort: uint16(srcAddrPort.Port()),
			DestPort:   uint16(dstAddrPort.Port()),
			NextHeader: proto,
			Flags:      TUPLE_F_OUT,
		},
	}
	// CTmap has the addresses in the reverse order w.r.t. the original direction
	key.SourceAddr.FromAddr(dstAddrPort.Addr())
	key.DestAddr.FromAddr(srcAddrPort.Addr())
	if ingress {
		key.Flags = TUPLE_F_IN
	}
	return key.ToNetwork(), false, nil
}

func getMapName(mapname string, ipv4 bool, proto u8proto.U8proto) string {
	if ipv4 {
		if proto == u8proto.TCP {
			mapname = MapNameTCP4 + mapname
		} else {
			mapname = MapNameAny4 + mapname
		}
	} else {
		if proto == u8proto.TCP {
			mapname = MapNameTCP6 + mapname
		} else {
			mapname = MapNameAny6 + mapname
		}
	}
	return mapname
}

func getOrOpenMap(epname string, ipv4 bool, proto u8proto.U8proto) (*bpf.Map, error) {
	mapname := getMapName(epname, ipv4, proto)
	if m := bpf.GetMap(mapname); m != nil {
		return m, nil
	}

	if epname == "global" {
		if ipv4 {
			return bpf.OpenMap(bpf.MapPath(mapname), &CtKey4Global{}, &CtEntry{})
		}

		return bpf.OpenMap(bpf.MapPath(mapname), &CtKey6Global{}, &CtEntry{})
	}

	if ipv4 {
		return bpf.OpenMap(bpf.MapPath(mapname), &CtKey4{}, &CtEntry{})
	}

	return bpf.OpenMap(bpf.MapPath(mapname), &CtKey6{}, &CtEntry{})
}

// Lookup opens a conntrack map if necessary, and does a lookup on it with a key constructed from
// the parameters
// 'epname' is a 5-digit representation of the endpoint ID if local maps
// are to be used, or "global" if global maps should be used.
func Lookup(epname string, srcAddr, dstAddr string, proto u8proto.U8proto, ingress bool) (*CtEntry, error) {
	isGlobal := epname == "global"

	key, ipv4, err := createTupleKey(isGlobal, srcAddr, dstAddr, proto, ingress)
	if err != nil {
		return nil, err
	}

	m, err := getOrOpenMap(epname, ipv4, proto)
	if err != nil || m == nil {
		return nil, err
	}

	v, err := m.Lookup(key)
	if err != nil || v == nil {
		return nil, err
	}

	return v.(*CtEntry), err
}

// Update opens a conntrack map if necessary, and does a lookup on it with a key constructed from
// the parameters, and updates the found entry (if any) via 'updateFn'.
// 'epname' is a 5-digit representation of the endpoint ID if local maps
// are to be used, or "global" if global maps should be used.
func Update(epname string, srcAddr, dstAddr string, proto u8proto.U8proto, ingress bool,
	updateFn func(*CtEntry) error) error {
	isGlobal := epname == "global"

	key, ipv4, err := createTupleKey(isGlobal, srcAddr, dstAddr, proto, ingress)
	if err != nil {
		return err
	}

	m, err := getOrOpenMap(epname, ipv4, proto)
	if err != nil || m == nil {
		return err
	}

	v, err := m.Lookup(key)
	if err != nil || v == nil {
		return err
	}

	entry := v.(*CtEntry)
	err = updateFn(entry)
	if err != nil {
		return err
	}

	return m.Update(key, entry)
}

func getMapWithName(epname string, ipv4 bool, proto u8proto.U8proto) *bpf.Map {
	return bpf.GetMap(getMapName(epname, ipv4, proto))
}

// CloseLocalMaps closes all local conntrack maps opened previously
// for lookup with the given 'mapname'.
func CloseLocalMaps(mapname string) {
	// only close local maps. Global map is kept open as long as cilium-agent is running.
	if mapname != "global" {
		// close IPv4 maps, if any
		if m := getMapWithName(mapname, true, u8proto.TCP); m != nil {
			m.Close()
		}
		if m := getMapWithName(mapname, true, u8proto.UDP); m != nil {
			m.Close()
		}

		// close IPv6 maps, if any
		if m := getMapWithName(mapname, false, u8proto.TCP); m != nil {
			m.Close()
		}
		if m := getMapWithName(mapname, false, u8proto.UDP); m != nil {
			m.Close()
		}
	}
}
