// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/u8proto"
)

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

func getMapWithName(logger *slog.Logger, epname string, ipv4 bool, proto u8proto.U8proto) *bpf.Map {
	return bpf.GetMap(logger, getMapName(epname, ipv4, proto))
}

// CloseLocalMaps closes all local conntrack maps opened previously
// for lookup with the given 'mapname'.
func CloseLocalMaps(logger *slog.Logger, mapname string) {
	// only close local maps. Global map is kept open as long as cilium-agent is running.
	if mapname != "global" {
		// close IPv4 maps, if any
		if m := getMapWithName(logger, mapname, true, u8proto.TCP); m != nil {
			m.Close()
		}
		if m := getMapWithName(logger, mapname, true, u8proto.UDP); m != nil {
			m.Close()
		}

		// close IPv6 maps, if any
		if m := getMapWithName(logger, mapname, false, u8proto.TCP); m != nil {
			m.Close()
		}
		if m := getMapWithName(logger, mapname, false, u8proto.UDP); m != nil {
			m.Close()
		}
	}
}
