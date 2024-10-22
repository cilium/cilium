// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package recorder

import (
	"strings"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	// MapNameWcard4 represents IPv4 capture wildcard table.
	MapNameWcard4 = "cilium_capture4_rules"
	// MapNameWcard6 represents IPv6 capture wildcard table.
	MapNameWcard6 = "cilium_capture6_rules"
	// MapSize is the default size of the v4 and v6 maps
	MapSize = 16384
)

type CaptureRule struct {
	RuleId   uint16 `align:"rule_id"`
	Reserved uint16 `align:"reserved"`
	CapLen   uint32 `align:"cap_len"`
}

type CaptureMap interface {
	Open() error
	Close() error
	Path() (string, error)
	DumpEntries() (string, error)
	DumpWithCallback(bpf.DumpCallback) error
}

type Map struct {
	bpf.Map
	v4 bool
}

type RecorderKey interface {
	bpf.MapKey
	ToHost() RecorderKey
	Dump(sb *strings.Builder)
	Map() *bpf.Map
}

type RecorderEntry interface {
	bpf.MapValue
	Dump(sb *strings.Builder)
}

type MapRecord struct {
	Key   RecorderKey
	Value RecorderEntry
}

func (m *Map) DumpEntries() (string, error) {
	var sb strings.Builder

	cb := func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(RecorderKey)
		key.ToHost().Dump(&sb)
		val := v.(RecorderEntry)
		val.Dump(&sb)
	}
	err := m.DumpWithCallback(cb)
	return sb.String(), err
}
