// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package signalmap

import (
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	// MapName is the BPF map name.
	MapName = "cilium_signals"

	// ringBufSize must match SIGNAL_RINGBUF_SIZE in bpf/lib/signal.h
	ringBufSize = 256 * 1024
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
	logger  *slog.Logger
	ebpfMap *ebpf.Map
}

// initMap creates the signal map in the kernel.
func initMap(logger *slog.Logger) *signalMap {
	return &signalMap{
		logger: logger,
	}
}

func (sm *signalMap) open() error {
	// For ringbuf, the map is created by BPF loader when the program is loaded.
	// We just need to load the pinned map.
	path := bpf.MapPath(sm.logger, MapName)

	var err error
	sm.ebpfMap, err = ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		// If the map doesn't exist yet, that's OK - the BPF programs haven't
		// been loaded yet. The signal manager will handle this gracefully.
		if errors.Is(err, os.ErrNotExist) {
			sm.logger.Info("Signal map not found, will be created when BPF programs are loaded",
				"path", path)
			return nil
		}
		return err
	}

	// Verify the map type is RingBuf. If it's the old PerfEventArray type,
	// we need to delete it so the BPF loader can recreate it with the correct type.
	mapType := sm.ebpfMap.Type()
	if mapType != ebpf.RingBuf {
		sm.logger.Info("Signal map has wrong type, unpinning for recreation by BPF loader",
			"expected", ebpf.RingBuf.String(),
			"actual", mapType.String(),
			"path", path)
		// Unpin the old map so BPF loader can create a new one
		if unpinErr := sm.ebpfMap.Unpin(); unpinErr != nil {
			sm.logger.Warn("Failed to unpin old signal map", "error", unpinErr)
		}
		sm.ebpfMap.Close()
		sm.ebpfMap = nil
		// Return nil so startup continues - the BPF loader will create the correct map
		return nil
	}

	return nil
}

func (sm *signalMap) close() error {
	if sm.ebpfMap != nil {
		return sm.ebpfMap.Close()
	}
	return nil
}

func (sm *signalMap) NewReader() (RingBufReader, error) {
	if sm.ebpfMap == nil {
		return nil, fmt.Errorf("signal map not available")
	}
	return ringbuf.NewReader(sm.ebpfMap)
}

func (sm *signalMap) MapName() string {
	return MapName
}
