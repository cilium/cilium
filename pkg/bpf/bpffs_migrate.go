package bpf

import (
	"errors"
	"fmt"
	"io"
	"path/filepath"

	"encoding/binary"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
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
func StartBPFFSMigration(bpffsPath, elfPath string) error {
	coll, err := ebpf.LoadCollectionSpec(elfPath)
	if err != nil {
		return err
	}

	for name, spec := range coll.Maps {
		// Parse iproute2 bpf_elf_map's extra fields, if any.
		if err := parseExtra(spec, coll); err != nil {
			return fmt.Errorf("parsing extra bytes of ELF map definition %q:", name)
		}

		// Skip map specs without the pinning flag. Also takes care of skipping .data,
		// .rodata and .bss.
		if spec.Pinning == 0 {
			continue
		}

		// Re-pin the map with ':pending' suffix if incoming spec differs from
		// the currently-pinned map.
		if err := repinMap(bpffsPath, name, spec); err != nil {
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
func FinalizeBPFFSMigration(bpffsPath, elfPath string, revert bool) error {
	coll, err := ebpf.LoadCollectionSpec(elfPath)
	if err != nil {
		return err
	}

	for name, spec := range coll.Maps {
		// Parse iproute2 bpf_elf_map's extra fields, if any.
		if err := parseExtra(spec, coll); err != nil {
			return fmt.Errorf("parsing extra bytes of ELF map definition %q:", name)
		}

		// Skip map specs without the pinning flag. Also takes care of skipping .data,
		// .rodata and .bss.
		// Don't unpin existing maps if their new versions are missing the pinning flag.
		if spec.Pinning == 0 {
			continue
		}

		if err := finalizeMap(bpffsPath, name, revert); err != nil {
			return err
		}
	}

	return nil
}

// parseExtra parses extra bytes that appear at the end of a struct bpf_elf_map.
// If the Extra field is empty, the function is a no-op.
//
// The library supports parsing `struct bpf_map_def` out of the box, but Cilium
// uses `struct bpf_elf_map` instead, which is bigger.
// The 'extra' bytes are exposed in the Map's Extra field, and appear in the
// following order (all u32): id, pinning, inner_id, inner_idx.
func parseExtra(spec *ebpf.MapSpec, coll *ebpf.CollectionSpec) error {
	// Nothing to parse. This will be the case for BTF-style maps that have
	// built-in support for pinning and map-in-map.
	if spec.Extra.Len() == 0 {
		return nil
	}

	// Discard the id as it's not needed.
	if _, err := io.CopyN(io.Discard, &spec.Extra, 4); err != nil {
		return fmt.Errorf("reading id field: %v", err)
	}

	// Read the pinning field.
	var pinning uint32
	if err := binary.Read(&spec.Extra, coll.ByteOrder, &pinning); err != nil {
		return fmt.Errorf("reading pinning field: %v", err)
	}
	spec.Pinning = ebpf.PinType(pinning)

	return nil
}

// repinMap opens a map from bpffs by its pin in '<bpffs>/tc/globals/',
// compares its properties against the incoming spec and re-pins it to
// ':pending' if any of its properties differ.
func repinMap(bpffsPath string, name string, spec *ebpf.MapSpec) error {
	file := filepath.Join(bpffsPath, name)
	pinned, err := ebpf.LoadPinnedMap(file, nil)

	// Given map was not pinned, nothing to do.
	if errors.Is(err, unix.ENOENT) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("map not found at path %s: %v", name, err)
	}

	if pinned.Type() == spec.Type &&
		pinned.KeySize() == spec.KeySize &&
		pinned.ValueSize() == spec.ValueSize &&
		pinned.Flags() == spec.Flags &&
		pinned.MaxEntries() == spec.MaxEntries {
		return nil
	}

	dest := file + bpffsPending

	log.Infof("New version of map '%s' has different properties, re-pinning from '%s' to '%s'", name, file, dest)

	// Atomically re-pin the map to the its new path.
	if err := pinned.Pin(dest); err != nil {
		return err
	}

	return nil
}

// finalizeMap opens the ':pending' Map pin of the given named Map from bpffs.
// If the given map is not found in bppffs, returns nil.
// If revert is true, the map will be re-pinned back to its initial locations.
// If revert is false, the map will be unpinned.
func finalizeMap(bpffsPath, name string, revert bool) error {
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
		log.Infof("Reverting map pin from '%s' to '%s' after failed migration", file, dest)

		// Atomically re-pin the map to its original path.
		if err := pending.Pin(dest); err != nil {
			return err
		}

		return nil
	}

	log.Infof("Unpinning map '%s' after successful recreation", file)

	// Pending Map found on bpffs and its replacement was successfully loaded.
	// Unpin the old map since it no longer needs to be interacted with from userspace.
	return pending.Unpin()
}
