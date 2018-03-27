// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ctmap

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/policy"

	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger

const (
	MapName6       = "cilium_ct6_"
	MapName4       = "cilium_ct4_"
	MapName6Global = MapName6 + "global"
	MapName4Global = MapName4 + "global"

	MapNumEntriesLocal  = 64000
	MapNumEntriesGlobal = 1000000

	TUPLE_F_OUT     = 0
	TUPLE_F_IN      = 1
	TUPLE_F_RELATED = 2

	// MaxTime specifies the last possible time for GCFilter.Time
	MaxTime = math.MaxUint32

	noAction = iota
	modifyEntry
	deleteEntry
)

type CtType int

// CtKey is the interface describing keys to the conntrack maps.
type CtKey interface {
	bpf.MapKey

	// ToNetwork converts fields to network byte order.
	ToNetwork() CtKey

	// ToHost converts fields to host byte order.
	ToHost() CtKey

	// Dumps contents of key to buffer. Returns true if successful.
	Dump(buffer *bytes.Buffer) bool
}

// CtEntry represents an entry in the connection tracking table.
type CtEntry struct {
	rx_packets uint64
	rx_bytes   uint64
	tx_packets uint64
	tx_bytes   uint64
	lifetime   uint32
	flags      uint16
	// revnat is in network byte order
	revnat uint16
	// proxy_port is in network byte order
	proxy_port uint16
	src_sec_id uint32
}

// GetValuePtr returns the unsafe.Pointer for s.
func (c *CtEntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(c) }

// String returns the readable format
func (c *CtEntry) String() string {
	return fmt.Sprintf("expires=%d rx_packets=%d rx_bytes=%d tx_packets=%d tx_bytes=%d flags=%x revnat=%d proxyport=%d src_sec_id=%d\n",
		c.lifetime,
		c.rx_packets,
		c.rx_bytes,
		c.tx_packets,
		c.tx_bytes,
		c.flags,
		byteorder.NetworkToHost(c.revnat),
		byteorder.NetworkToHost(c.proxy_port),
		c.src_sec_id)
}

// CtEntryDump represents the key and value contained in the conntrack map.
type CtEntryDump struct {
	Key   CtKey
	Value CtEntry
}

const (
	// GCFilterNone doesn't filter the CT entries
	GCFilterNone = iota
	// GCFilterByTime filters CT entries by time
	GCFilterByTime
	// GCFilterByIDToMod modifies all CT entries with the new proxyport number
	// if they are matched by the filter.
	GCFilterByIDToMod
	// GCFilterByIDsToKeep removes all CT entries that do not match by the
	// filter.
	GCFilterByIDsToKeep
)

// GCFilterType is the type of a filter.
type GCFilterType uint

// GCFilter contains the necessary fields to filter the CT maps.
// Filtering by endpoint requires both EndpointID to be > 0 and
// EndpointIP to be not nil.
type GCFilter struct {
	Type       GCFilterType
	IDsToMod   policy.SecurityIDContexts
	IDsToKeep  policy.SecurityIDContexts
	Time       uint32
	EndpointID uint16
	EndpointIP net.IP
}

// NewGCFilterBy creates a new GCFilter of the given type.
func NewGCFilterBy(filterType GCFilterType) *GCFilter {
	return &GCFilter{
		Type:      filterType,
		IDsToMod:  policy.NewSecurityIDContexts(),
		IDsToKeep: policy.NewSecurityIDContexts(),
	}
}

// TypeString returns the filter type in human readable way.
func (f *GCFilter) TypeString() string {
	switch f.Type {
	case GCFilterNone:
		return "none"
	case GCFilterByTime:
		return "timeout"
	case GCFilterByIDToMod:
		return "security ID"
	case GCFilterByIDsToKeep:
		return "security ID to keep"
	default:
		return "(unknown)"
	}
}

// ToString iterates through Map m and writes the values of the ct entries in m
// to a string.
func ToString(m *bpf.Map, mapName string) (string, error) {
	var buffer bytes.Buffer
	entries, err := dumpToSlice(m, mapName)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if !entry.Key.ToHost().Dump(&buffer) {
			continue
		}

		value := entry.Value
		buffer.WriteString(
			fmt.Sprintf(" expires=%d rx_packets=%d rx_bytes=%d tx_packets=%d tx_bytes=%d flags=%x revnat=%d proxyport=%d src_sec_id=%d\n",
				value.lifetime,
				value.rx_packets,
				value.rx_bytes,
				value.tx_packets,
				value.tx_bytes,
				value.flags,
				byteorder.NetworkToHost(value.revnat),
				byteorder.NetworkToHost(value.proxy_port),
				value.src_sec_id,
			),
		)

	}
	return buffer.String(), nil
}

// DumpToSlice iterates through map m and returns a slice mapping each key to
// its value in m.
func dumpToSlice(m *bpf.Map, mapType string) ([]CtEntryDump, error) {
	entries := []CtEntryDump{}

	switch mapType {
	case MapName6, MapName6Global:
		var key, nextKey CtKey6Global
		for {
			err := m.GetNextKey(&key, &nextKey)
			if err != nil {
				break
			}

			entry, err := m.Lookup(&nextKey)
			if err != nil {
				return nil, err
			}
			ctEntry := entry.(*CtEntry)

			nK := nextKey
			eDump := CtEntryDump{Key: &nK, Value: *ctEntry}
			entries = append(entries, eDump)

			key = nextKey
		}

	case MapName4, MapName4Global:
		var key, nextKey CtKey4Global
		for {
			err := m.GetNextKey(&key, &nextKey)
			if err != nil {
				break
			}

			entry, err := m.Lookup(&nextKey)
			if err != nil {
				return nil, err
			}
			ctEntry := entry.(*CtEntry)

			nK := nextKey
			eDump := CtEntryDump{Key: &nK, Value: *ctEntry}
			entries = append(entries, eDump)

			key = nextKey
		}
	}
	return entries, nil
}

// doGC6 iterates through a CTv6 map and drops entries based on the given
// filter.
func doGC6(m *bpf.Map, filter *GCFilter) int {
	var (
		action, deleted int
		nextKey, tmpKey CtKey6Global
	)

	err := m.GetNextKey(&tmpKey, &nextKey)
	if err != nil {
		return 0
	}

	// If the filter is by ID and the IDsToMod is empty then skip GC.
	if filter.Type == GCFilterByIDToMod {
		if len(filter.IDsToMod) == 0 {
			return 0
		}
	}

	for {
		nextKeyValid := m.GetNextKey(&nextKey, &tmpKey)
		entryMap, err := m.Lookup(&nextKey)
		if err != nil {
			log.WithError(err).Error("error during map Lookup")
			break
		}

		entry := entryMap.(*CtEntry)

		// In CT entries, the source address of the conntrack entry (`saddr`) is
		// the destination of the packet received, therefore it's the packet's
		// destination IP
		action = filter.doFiltering(nextKey.daddr.IP(), nextKey.saddr.IP(), nextKey.sport, uint8(nextKey.nexthdr), nextKey.flags, entry)

		switch action {
		case modifyEntry:
			err = m.Update(&nextKey, entry)
			if err != nil {
				log.WithError(err).Errorf("Unable to change proxyport field for CT entry %s", nextKey.String())
			}
		case deleteEntry:
			err := m.Delete(&nextKey)
			if err != nil {
				log.WithError(err).Errorf("Unable to delete CT entry %s", nextKey.String())
			} else {
				deleted++
			}
		}

		if nextKeyValid != nil {
			break
		}
		nextKey = tmpKey
	}
	return deleted
}

// doGC4 iterates through a CTv4 map and drops entries based on the given
// filter.
func doGC4(m *bpf.Map, filter *GCFilter) int {
	var (
		action, deleted int
		nextKey, tmpKey CtKey4Global
	)

	err := m.GetNextKey(&tmpKey, &nextKey)
	if err != nil {
		return 0
	}

	// If the filter is by ID and the IDsToMod is empty then skip GC.
	if filter.Type == GCFilterByIDToMod {
		if len(filter.IDsToMod) == 0 {
			return 0
		}
	}

	for true {
		nextKeyValid := m.GetNextKey(&nextKey, &tmpKey)
		entryMap, err := m.Lookup(&nextKey)
		if err != nil {
			log.WithError(err).Error("error during map Lookup")
			break
		}

		entry := entryMap.(*CtEntry)

		// In CT entries, the source address of the conntrack entry (`saddr`) is
		// the destination of the packet received, therefore it's the packet's
		// destination IP
		action = filter.doFiltering(nextKey.daddr.IP(), nextKey.saddr.IP(), nextKey.sport, uint8(nextKey.nexthdr), nextKey.flags, entry)

		switch action {
		case modifyEntry:
			err = m.Update(&nextKey, entry)
			if err != nil {
				log.WithError(err).Errorf("Unable to change proxyport field for CT entry %s", nextKey.String())
			}
		case deleteEntry:
			err := m.Delete(&nextKey)
			if err != nil {
				log.WithError(err).Errorf("Unable to delete CT entry %s", nextKey.String())
			} else {
				deleted++
			}
		}

		if nextKeyValid != nil {
			break
		}
		nextKey = tmpKey
	}
	return deleted
}

func (f *GCFilter) doFiltering(srcIP net.IP, dstIP net.IP, dstPort uint16, nextHdr, flags uint8, entry *CtEntry) (action int) {
	scopedLog := log.WithFields(logrus.Fields{
		"entrySrcIP":       srcIP,
		"entryDstIP":       dstIP,
		"entryDstPort":     byteorder.NetworkToHost(dstPort),
		"entryProto":       nextHdr,
		"entryFlags":       flags,
		"entrySrcSecID":    entry.src_sec_id,
		"entryProxyPort":   byteorder.NetworkToHost(entry.proxy_port),
		"filterType":       f.TypeString(),
		"filterEndpointID": f.EndpointID,
		"filterEndpointIP": f.EndpointIP,
	})
	flowdebug.Log(scopedLog, "Filtering CT map entry")

	action = noAction

	// Delete all entries with a lifetime smaller than f timestamp.
	if f.Type == GCFilterByTime && entry.lifetime < f.Time {
		action = deleteEntry
		flowdebug.Log(scopedLog, "Deleting CT map entry: too old")
	}

	// If the filter doesn't contain an endpoint ID & IP, no entries will get matched below.
	if f.EndpointID == 0 || f.EndpointIP == nil {
		flowdebug.Log(scopedLog, "Ignoring CT map entry: no endpoint ID or IP given in filter")
		return
	}

	// Determine whether the entry matches the endpoint IP,
	// and the direction of the entry (ingress or egress).
	var ingress bool
	if flags&TUPLE_F_IN != 0 && dstIP.Equal(f.EndpointIP) {
		ingress = true
		flowdebug.Log(scopedLog, "Ingress CT map entry matches endpoint IP")
	} else if flags&TUPLE_F_IN == 0 && srcIP.Equal(f.EndpointIP) {
		ingress = false
		flowdebug.Log(scopedLog, "Egress CT map entry matches endpoint IP")
	} else {
		// Didn't match the endpoint IP.
		flowdebug.Log(scopedLog, "Ignoring CT map entry: didn't match endpoint IP")
		return
	}

	l4RuleCtx := policy.L4RuleContext{
		EndpointID: f.EndpointID,
		Ingress:    ingress,
		Port:       dstPort,
		Proto:      nextHdr,
	}

	switch f.Type {

	// Used by FlushCTEntriesOf.
	// Delete all entries of the given endpoint IP that are not filtered.
	case GCFilterByIDsToKeep:
		// Check if the src_sec_id of that entry is still allowed
		// to talk with the destination IP.
		filterRuleCtx, ok := f.IDsToKeep[identity.NumericIdentity(entry.src_sec_id)]
		if !ok {
			action = deleteEntry
			flowdebug.Log(scopedLog, "Deleting CT map entry: src sec ID is no more allowed by policy")
			return
		}

		if filterRuleCtx.IsL3Only() {
			// If the rule is L3-only then check whether that entry is denied by
			// L4-only rules.
			filterRuleCtx, ok = f.IDsToKeep[identity.InvalidIdentity]
			if !ok {
				flowdebug.Log(scopedLog, "Ignoring CT map entry: allowed by L3-only rule")
				return
			}
		}

		l7RuleCtx, ok := filterRuleCtx[l4RuleCtx]
		if !ok {
			action = deleteEntry
			flowdebug.Log(scopedLog, "Deleting CT map entry: not allowed by any L4+ rule")
			return
		}

		flowdebug.Logf(scopedLog, "Evaluating L7 rule context: RedirectPort=%d, L4Installed=%t",
			byteorder.NetworkToHost(l7RuleCtx.RedirectPort), l7RuleCtx.L4Installed)

		if l7RuleCtx.L4Installed && entry.proxy_port != l7RuleCtx.RedirectPort {
			action = modifyEntry
			flowdebug.Logf(scopedLog, "Modifying CT map entry: setting proxy port to %d",
				byteorder.NetworkToHost(l7RuleCtx.RedirectPort))
			entry.proxy_port = l7RuleCtx.RedirectPort
			return
		}

	// Used by ModifyEntriesOf.
	case GCFilterByIDToMod:
		// Check if the src_sec_id of that entry needs to be modified
		// by the given filter.
		filterRuleCtx, ok := f.IDsToMod[identity.NumericIdentity(entry.src_sec_id)]
		if !ok {
			flowdebug.Log(scopedLog, "Ignoring CT map entry: src sec ID is no more allowed by policy")
			return
		}

		if filterRuleCtx.IsL3Only() {
			// If the rule is L3-only then check whether that entry is denied by
			// L4-only rules.
			filterRuleCtx, ok = f.IDsToKeep[identity.InvalidIdentity]
			if !ok {
				flowdebug.Log(scopedLog, "Ignoring CT map entry: not allowed by L4-only rules")
				return
			}
		}

		l7RuleCtx, ok := filterRuleCtx[l4RuleCtx]
		if !ok {
			flowdebug.Log(scopedLog, "Ignoring CT map entry: not allowed by any L4+ rule")
			return
		}

		flowdebug.Logf(scopedLog, "Evaluating L7 rule context: RedirectPort=%d, L4Installed=%t",
			byteorder.NetworkToHost(l7RuleCtx.RedirectPort), l7RuleCtx.L4Installed)

		if l7RuleCtx.L4Installed && l7RuleCtx.IsRedirect() && entry.proxy_port != 0 {
			action = modifyEntry
			flowdebug.Logf(scopedLog, "Modifying CT map entry: setting proxy port to %d", 0)
			entry.proxy_port = 0
			return
		}
	}

	flowdebug.Log(scopedLog, "Ignoring CT map entry: no action required")
	return
}

// GC runs garbage collection for map m with name mapName with the given filter.
// It returns how many items were deleted from m.
func GC(m *bpf.Map, mapName string, filter *GCFilter) int {
	if filter.Type == GCFilterByTime {
		// If LRUHashtable, no need to garbage collect as LRUHashtable cleans itself up.
		// FIXME: GH-3239 LRU logic is not handling timeouts gracefully enough
		// if m.MapInfo.MapType == bpf.MapTypeLRUHash {
		// 	return 0
		// }
		t, _ := bpf.GetMtime()
		tsec := t / 1000000000
		filter.Time = uint32(tsec)
	}

	switch mapName {
	case MapName6, MapName6Global:
		return doGC6(m, filter)
	case MapName4, MapName4Global:
		return doGC4(m, filter)
	default:
		return 0
	}
}

// Flush runs garbage collection for map m with the name mapName, deleting all
// entries. The specified map must be already opened using bpf.OpenMap().
func Flush(m *bpf.Map, mapName string) int {
	filter := NewGCFilterBy(GCFilterByTime)
	filter.Time = MaxTime

	switch mapName {
	case MapName6, MapName6Global:
		return doGC6(m, filter)
	case MapName4, MapName4Global:
		return doGC4(m, filter)
	default:
		return 0
	}
}
