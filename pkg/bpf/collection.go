package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// LoadCollectionSpec loads the eBPF ELF at the given path and parses it into
// a CollectionSpec. This spec is only a blueprint of the contents of the ELF
// and does not represent any live resources that have been loaded into the
// kernel.
//
// This is a wrapper around ebpf.LoadCollectionSpec that parses legacy iproute2
// bpf_elf_map definitions (only used for prog_arrays at the time of writing)
// and assigns tail calls annotated with `__section_tail` macros to their
// intended maps and slots.
func LoadCollectionSpec(path string) (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, err
	}

	if err := iproute2Compat(spec); err != nil {
		return nil, err
	}

	classifyProgramTypes(spec)

	return spec, nil
}

// iproute2Compat parses the Extra field of each MapSpec in the CollectionSpec.
// This extra portion is present in legacy bpf_elf_map definitions and must be
// handled before the map can be loaded into the kernel.
//
// It parses the ELF section name of each ProgramSpec to extract any map/slot
// mappings for prog arrays used as tail call maps. The spec's programs are then
// inserted into the appropriate map and slot.
//
// TODO(timo): Remove when bpf_elf_map map definitions are no longer used after
// moving away from iproute2+libbpf.
func iproute2Compat(spec *ebpf.CollectionSpec) error {
	// Parse legacy iproute2 u32 id and pinning fields.
	maps := make(map[uint32]*ebpf.MapSpec)
	for _, m := range spec.Maps {
		if m.Extra != nil && m.Extra.Len() > 0 {
			tail := struct {
				ID      uint32
				Pinning uint32
				_       uint64 // inner_id + inner_idx
			}{}
			if err := binary.Read(m.Extra, spec.ByteOrder, &tail); err != nil {
				return fmt.Errorf("reading iproute2 map definition: %w", err)
			}

			if tail.Pinning > 0 {
				m.Pinning = 1 // LIBBPF_PIN_BY_NAME
			}

			// Index maps by their iproute2 .id if any, so X/Y ELF section names can
			// be matched against them.
			if tail.ID != 0 {
				if m2 := maps[tail.ID]; m2 != nil {
					return fmt.Errorf("maps %s and %s have duplicate iproute2 map ID %d", m.Name, m2.Name, tail.ID)
				}
				maps[tail.ID] = m
			}
		}
	}

	for n, p := range spec.Programs {
		// Parse the program's section name to determine which prog array and slot it
		// needs to be inserted into. For example, a section name of '2/14' means to
		// insert into the map with the .id field of 2 at index 14.
		// Uses %v to automatically detect slot's mathematical base, since they can
		// appear either in dec or hex, e.g. 1/0x0515.
		var id, slot uint32
		if _, err := fmt.Sscanf(p.SectionName, "%d/%v", &id, &slot); err == nil {
			// Assign the prog name and slot to the map with the iproute2 .id obtained
			// from the program's section name. The lib will load the ProgramSpecs
			// and insert the corresponding Programs into the prog array at load time.
			m := maps[id]
			if m == nil {
				return fmt.Errorf("no map with iproute2 map .id %d", id)
			}
			m.Contents = append(maps[id].Contents, ebpf.MapKV{Key: slot, Value: n})
		}
	}

	return nil
}

// LoadCollection loads the given spec into the kernel with the specified opts.
//
// Any maps marked as pinned in the spec are automatically loaded from the path
// given in opts.Maps.PinPath and will be used instead of creating new ones.
// MapSpecs that differ (type/key/value/max/flags) from their pinned versions
// will result in an ebpf.ErrMapIncompatible here and the map must be removed
// before loading the CollectionSpec.
func LoadCollection(spec *ebpf.CollectionSpec, opts ebpf.CollectionOptions) (*ebpf.Collection, error) {
	if spec == nil {
		return nil, errors.New("can't load nil CollectionSpec")
	}

	// By default, allocate a 1MiB verifier log buffer if first load attempt
	// fails. This was adjusted around Cilium 1.11 for fitting bpf_lxc insn
	// limit messages.
	if opts.Programs.LogSize == 0 {
		opts.Programs.LogSize = 1 << 20
	}

	// Copy spec so the modifications below don't affect the input parameter,
	// allowing the spec to be safely re-used by the caller.
	spec = spec.Copy()

	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, err
	}

	return coll, nil
}

// classifyProgramTypes sets the type of ProgramSpecs which the library cannot
// automatically classify due to them being in unrecognized ELF sections. Only
// programs of type UnspecifiedProgram are modified.
//
// Cilium uses the iproute2 X/Y section name convention for assigning programs
// to prog array slots, which is also not supported.
func classifyProgramTypes(spec *ebpf.CollectionSpec) {
	// Assign a program type based on the first recognized function name.
	var t ebpf.ProgramType
	for name := range spec.Programs {
		switch name {
		// bpf_xdp.c
		case "bpf_xdp_entry":
			t = ebpf.XDP
		case
			// bpf_lxc.c
			"handle_xgress", "handle_to_container",
			// bpf_host.c
			"from_netdev", "from_host", "to_netdev", "to_host",
			// bpf_network.c
			"from_network",
			// bpf_overlay.c
			"to_overlay", "from_overlay":
			t = ebpf.SchedCLS
		default:
			continue
		}

		break
	}

	for _, p := range spec.Programs {
		if p.Type == ebpf.UnspecifiedProgram {
			p.Type = t
		}
	}
}
