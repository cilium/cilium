// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eventsmap

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// MapName is the BPF map name.
	MapName = "cilium_events"
)

// Key is the index into the prog array map.
type Key struct {
	index uint32
}

// Value is the program ID in the prog array map.
type Value struct {
	progID uint32
}

// String converts the key into a human readable string format.
func (k *Key) String() string  { return fmt.Sprintf("%d", k.index) }
func (k *Key) New() bpf.MapKey { return &Key{} }

// String converts the value into a human readable string format.
func (v *Value) String() string    { return fmt.Sprintf("%d", v.progID) }
func (v *Value) New() bpf.MapValue { return &Value{} }

type eventsMap struct {
	m *bpf.Map
}

// init creates the events map in the kernel.
func (e *eventsMap) init(maxEntries int) error {
	e.m = bpf.NewMap(MapName,
		ebpf.PerfEventArray,
		&Key{},
		&Value{},
		maxEntries,
		0).
		WithEvents(option.Config.GetEventBufferConfig(MapName))
	return e.m.Create()
}
