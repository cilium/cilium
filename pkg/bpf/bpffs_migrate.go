// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

const bpffsPending = ":pending"

// StartBPFFSMigration the map migration process for a given ELF's maps.
// When a new ELF contains a map definition that differs from its existing (pinned)
// counterpart, re-pin it to its current path suffixed by ':pending'.
// A map's type, key size, value size, flags and max entries are compared to the given spec.
//
// Takes a bpffsPath explicitly since it does not necessarily execute within
// the same runtime as the agent. It is imported from a Cilium cmd that takes
// its bpffs path from an env.
func StartBPFFSMigration(bpffsPath string, coll *ebpf.CollectionSpec) error {
	if coll == nil {
		return errors.New("can't migrate a nil CollectionSpec")
	}

	for name, spec := range coll.Maps {
		// Skip map specs without the pinning flag. Also takes care of skipping .data,
		// .rodata and .bss.
		if spec.Pinning == 0 {
			continue
		}

		// Re-pin the map with ':pending' suffix if incoming spec differs from
		// the currently-pinned map.
		if err := RepinMap(bpffsPath, name, spec); err != nil {
			return err
		}
	}

	return nil
}

// FinalizeBPFFSMigration finalizes the migration of an ELF's maps.
// If revert is true, any pending maps are re-pinned back to their original
// locations. If revert is false, any pending maps are unpinned (deleted).
//
// Takes a bpffsPath explicitly since it does not necessarily execute within
// the same runtime as the agent. It is imported from a Cilium cmd that takes
// its bpffs path from an env.
func FinalizeBPFFSMigration(bpffsPath string, coll *ebpf.CollectionSpec, revert bool) error {
	if coll == nil {
		return errors.New("can't migrate a nil CollectionSpec")
	}

	for name, spec := range coll.Maps {
		// Skip map specs without the pinning flag. Also takes care of skipping .data,
		// .rodata and .bss.
		// Don't unpin existing maps if their new versions are missing the pinning flag.
		if spec.Pinning == 0 {
			continue
		}

		if err := FinalizeMap(bpffsPath, name, revert); err != nil {
			return err
		}
	}

	return nil
}

// RepinMap opens a map from bpffs by its pin in '<bpffs>/tc/globals/',
// compares its properties against the incoming spec and re-pins it to
// ':pending' if any of its properties differ.
func RepinMap(bpffsPath string, name string, spec *ebpf.MapSpec) error {
	file := filepath.Join(bpffsPath, name)
	pinned, err := ebpf.LoadPinnedMap(file, nil)

	// Given map was not pinned, nothing to do.
	if errors.Is(err, unix.ENOENT) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("map not found at path %s: %v", name, err)
	}
	defer pinned.Close()

	if pinned.Type() == spec.Type &&
		pinned.KeySize() == spec.KeySize &&
		pinned.ValueSize() == spec.ValueSize &&
		pinned.Flags() == spec.Flags &&
		pinned.MaxEntries() == spec.MaxEntries {
		// cilium_calls_xdp is shared between XDP interfaces and should only be
		// migrated if the existing map is incompatible.
		if spec.Name == "cilium_calls_xdp" {
			return nil
		}
		// Maps prefixed with cilium_calls_ should never be reused by subsequent ELF
		// loads and should be migrated unconditionally.
		if !strings.HasPrefix(spec.Name, "cilium_calls_") {
			return nil
		}
	}

	dest := file + bpffsPending

	log.WithFields(logrus.Fields{
		logfields.BPFMapName: name,
		logfields.BPFMapPath: file,
	}).Infof("Re-pinning map with '%s' suffix", bpffsPending)

	if err := os.Remove(dest); err == nil {
		log.WithFields(logrus.Fields{
			logfields.BPFMapName: name,
			logfields.BPFMapPath: dest,
		}).Info("Removed pending pinned map, did the agent die unexpectedly?")
	}

	// Atomically re-pin the map to its new path.
	if err := pinned.Pin(dest); err != nil {
		return err
	}

	return nil
}

// FinalizeMap opens the ':pending' Map pin of the given named Map from bpffs.
// If the given map is not found in bpffs, returns nil.
// If revert is true, the map will be re-pinned back to its initial locations.
// If revert is false, the map will be unpinned.
func FinalizeMap(bpffsPath, name string, revert bool) error {
	// Attempt to open a 'pending' Map pin.
	file := filepath.Join(bpffsPath, name+bpffsPending)
	pending, err := ebpf.LoadPinnedMap(file, nil)

	// Given map was not pending recreation, nothing to do.
	if errors.Is(err, unix.ENOENT) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("unable to open pinned map at path %s: %v", name, err)
	}

	// Pending Map was found on bpffs and needs to be reverted.
	if revert {
		dest := filepath.Join(bpffsPath, name)
		log.WithFields(logrus.Fields{
			logfields.BPFMapPath: dest,
			logfields.BPFMapName: name,
		}).Infof("Repinning without '%s' suffix after failed migration", bpffsPending)

		if err := os.Remove(dest); err == nil {
			log.WithFields(logrus.Fields{
				logfields.BPFMapName: name,
				logfields.BPFMapPath: dest,
			}).Warn("Removed new pinned map after failed migration")
		}

		// Atomically re-pin the map to its original path.
		if err := pending.Pin(dest); err != nil {
			return err
		}

		return nil
	}

	log.WithFields(logrus.Fields{
		logfields.BPFMapPath: file,
		logfields.BPFMapName: name,
	}).Info("Unpinning map after successful recreation")

	// Pending Map found on bpffs and its replacement was successfully loaded.
	// Unpin the old map since it no longer needs to be interacted with from userspace.
	return pending.Unpin()
}
