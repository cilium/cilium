// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bpf

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/spanstat"
)

// createMap wraps a call to ebpf.NewMapWithOptions while measuring syscall duration.
func createMap(spec *ebpf.MapSpec, opts *ebpf.MapOptions) (*ebpf.Map, error) {
	if opts == nil {
		opts = &ebpf.MapOptions{}
	}

	var duration *spanstat.SpanStat
	if metrics.BPFSyscallDuration.IsEnabled() {
		duration = spanstat.Start()
	}

	m, err := ebpf.NewMapWithOptions(spec, *opts)

	if metrics.BPFSyscallDuration.IsEnabled() {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpCreate, metrics.Error2Outcome(err)).Observe(duration.End(err == nil).Total().Seconds())
	}

	return m, err
}

func objCheck(logger *slog.Logger, m *ebpf.Map, path string, mapType ebpf.MapType, keySize, valueSize, maxEntries, flags uint32) bool {
	scopedLogger := logger.With(logfields.Path, path)
	mismatch := false

	if m.Type() != mapType {
		scopedLogger.Warn("Map type mismatch for BPF map",
			logfields.Old, m.Type(),
			logfields.New, mapType,
		)
		mismatch = true
	}

	if m.KeySize() != keySize {
		scopedLogger.Warn("Key-size mismatch for BPF map",
			logfields.Old, m.KeySize(),
			logfields.New, keySize,
		)
		mismatch = true
	}

	if m.ValueSize() != valueSize {
		scopedLogger.Warn("Value-size mismatch for BPF map",
			logfields.Old, m.ValueSize(),
			logfields.New, valueSize,
		)
		mismatch = true
	}

	if m.MaxEntries() != maxEntries {
		scopedLogger.Warn("Max entries mismatch for BPF map",
			logfields.Old, m.MaxEntries(),
			logfields.New, maxEntries,
		)
		mismatch = true
	}
	if m.Flags() != flags {
		scopedLogger.Warn("Flags mismatch for BPF map",
			logfields.Old, m.Flags(),
			logfields.New, flags,
		)
		mismatch = true
	}

	if mismatch {
		if m.Type() == ebpf.ProgramArray {
			return false
		}

		scopedLogger.Warn("Removing map to allow for property upgrade (expect map data loss)")

		// Kernel still holds map reference count via attached prog.
		// Only exception is prog array, but that is already resolved
		// differently.
		os.Remove(path)
		return true
	}

	return false
}

// OpenOrCreateMap attempts to load the pinned map at "pinDir/<spec.Name>" if
// the spec is marked as Pinned. Any parent directories of pinDir are
// automatically created. Any pinned maps incompatible with the given spec are
// removed and recreated.
//
// If spec.Pinned is 0, a new Map is always created.
func OpenOrCreateMap(logger *slog.Logger, spec *ebpf.MapSpec, pinDir string) (*ebpf.Map, error) {
	var opts ebpf.MapOptions
	if spec.Pinning != 0 {
		if pinDir == "" {
			return nil, errors.New("cannot pin map to empty pinDir")
		}
		if spec.Name == "" {
			return nil, errors.New("cannot load unnamed map from pin")
		}

		if err := MkdirBPF(pinDir); err != nil {
			return nil, fmt.Errorf("creating map base pinning directory: %w", err)
		}

		opts.PinPath = pinDir
	}

	m, err := createMap(spec, &opts)
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		// Found incompatible map. Open the pin again to find out why.
		m, err := ebpf.LoadPinnedMap(path.Join(pinDir, spec.Name), nil)
		if err != nil {
			return nil, fmt.Errorf("open pin of incompatible map: %w", err)
		}
		defer m.Close()

		logger.Info(
			"Unpinning map with incompatible properties",
			logfields.Path, path.Join(pinDir, spec.Name),
			logfields.Old, []any{
				logfields.Type, m.Type(),
				logfields.KeySize, m.KeySize(),
				logfields.ValueSize, m.ValueSize(),
				logfields.MaxEntries, m.MaxEntries(),
				logfields.Flags, m.Flags(),
			},
			logfields.New, []any{
				logfields.Type, spec.Type,
				logfields.KeySize, spec.KeySize,
				logfields.ValueSize, spec.ValueSize,
				logfields.MaxEntries, spec.MaxEntries,
				logfields.Flags, spec.Flags,
			},
		)

		// Existing map incompatible with spec. Unpin so it can be recreated.
		if err := m.Unpin(); err != nil {
			return nil, err
		}

		return createMap(spec, &opts)
	}

	return m, err
}

// GetMtime returns monotonic time that can be used to compare
// values with ktime_get_ns() BPF helper, e.g. needed to check
// the timeout in sec for BPF entries. We return the raw nsec,
// although that is not quite usable for comparison. Go has
// runtime.nanotime() but doesn't expose it as API.
func GetMtime() (uint64, error) {
	var ts unix.Timespec

	err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	if err != nil {
		return 0, fmt.Errorf("Unable get time: %w", err)
	}

	return uint64(unix.TimespecToNsec(ts)), nil
}
