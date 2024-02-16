// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package bpf

import (
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
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

func objCheck(m *ebpf.Map, path string, mapType ebpf.MapType, keySize, valueSize, maxEntries, flags uint32) bool {
	scopedLog := log.WithField(logfields.Path, path)
	mismatch := false

	if m.Type() != mapType {
		scopedLog.WithFields(logrus.Fields{
			"old": m.Type(),
			"new": mapType,
		}).Warning("Map type mismatch for BPF map")
		mismatch = true
	}

	if m.KeySize() != keySize {
		scopedLog.WithFields(logrus.Fields{
			"old": m.KeySize(),
			"new": keySize,
		}).Warning("Key-size mismatch for BPF map")
		mismatch = true
	}

	if m.ValueSize() != valueSize {
		scopedLog.WithFields(logrus.Fields{
			"old": m.ValueSize(),
			"new": valueSize,
		}).Warning("Value-size mismatch for BPF map")
		mismatch = true
	}

	if m.MaxEntries() != maxEntries {
		scopedLog.WithFields(logrus.Fields{
			"old": m.MaxEntries(),
			"new": maxEntries,
		}).Warning("Max entries mismatch for BPF map")
		mismatch = true
	}
	if m.Flags() != flags {
		scopedLog.WithFields(logrus.Fields{
			"old": m.Flags(),
			"new": flags,
		}).Warning("Flags mismatch for BPF map")
		mismatch = true
	}

	if mismatch {
		if m.Type() == ebpf.ProgramArray {
			return false
		}

		scopedLog.Warning("Removing map to allow for property upgrade (expect map data loss)")

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
func OpenOrCreateMap(spec *ebpf.MapSpec, pinDir string) (*ebpf.Map, error) {
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

		log.WithField(logfields.Path, path.Join(pinDir, spec.Name)).
			WithFields(logrus.Fields{
				"old": fmt.Sprintf("Type:%s KeySize:%d ValueSize:%d MaxEntries:%d Flags:%d",
					m.Type(), m.KeySize(), m.ValueSize(), m.MaxEntries(), m.Flags()),
				"new": fmt.Sprintf("Type:%s KeySize:%d ValueSize:%d MaxEntries:%d Flags:%d",
					spec.Type, spec.KeySize, spec.ValueSize, spec.MaxEntries, spec.Flags),
			}).Info("Unpinning map with incompatible properties")

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
		return 0, fmt.Errorf("Unable get time: %s", err)
	}

	return uint64(unix.TimespecToNsec(ts)), nil
}
