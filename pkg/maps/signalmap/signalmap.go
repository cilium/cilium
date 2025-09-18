// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package signalmap

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	// MapName is the BPF map name.
	MapName = "cilium_signals"
)

// Key is the index into the prog array map.
type Key struct {
	Index uint32
}

// Value is the program ID in the prog array map.
type Value struct {
	ProgID uint32
}

// String converts the key into a human readable string format.
func (k *Key) String() string  { return fmt.Sprintf("%d", k.Index) }
func (k *Key) New() bpf.MapKey { return &Key{} }

// String converts the value into a human readable string format.
func (v *Value) String() string    { return fmt.Sprintf("%d", v.ProgID) }
func (v *Value) New() bpf.MapValue { return &Value{} }

type signalMap struct {
	logger     *slog.Logger
	oldBpfMap  *bpf.Map
	ebpfMap    *ebpf.Map
	maxEntries int
}

// initMap creates the signal map in the kernel.
func initMap(logger *slog.Logger, maxEntries int) *signalMap {
	return &signalMap{
		logger:     logger,
		maxEntries: maxEntries,
		oldBpfMap: bpf.NewMap(MapName,
			ebpf.PerfEventArray,
			&Key{},
			&Value{},
			maxEntries,
			0,
		),
	}
}

func (sm *signalMap) open() error {
	if err := sm.oldBpfMap.Create(); err != nil {
		return err
	}
	path := bpf.MapPath(sm.logger, MapName)

	var err error
	sm.ebpfMap, err = ebpf.LoadPinnedMap(path, nil)
	return err
}

func (sm *signalMap) close() error {
	if sm.ebpfMap != nil {
		return sm.ebpfMap.Close()
	}
	return nil
}

func (sm *signalMap) NewReader() (PerfReader, error) {
	return perf.NewReader(sm.ebpfMap, os.Getpagesize())
}

func (sm *signalMap) MapName() string {
	return MapName
}
