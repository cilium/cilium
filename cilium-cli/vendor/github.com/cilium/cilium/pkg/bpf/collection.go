// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

const globalDataMap = ".rodata.config"

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

	if err := classifyProgramTypes(spec); err != nil {
		return nil, err
	}

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
				m.Pinning = ebpf.PinByName
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
// The value given in ProgramOptions.LogSize is used as the starting point for
// sizing the verifier's log buffer and defaults to 4MiB. On each retry, the
// log buffer quadruples in size, for a total of 5 attempts. If that proves
// insufficient, a truncated ebpf.VerifierError is returned.
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

	// Copy spec so the modifications below don't affect the input parameter,
	// allowing the spec to be safely re-used by the caller.
	spec = spec.Copy()

	if err := inlineGlobalData(spec); err != nil {
		return nil, fmt.Errorf("inlining global data: %w", err)
	}

	// Set initial size of verifier log buffer.
	//
	// Up until kernel 5.1, the maximum log size is (2^24)-1. In 5.2, this was
	// increased to (2^30)-1 by 7a9f5c65abcc ("bpf: increase verifier log limit").
	//
	// The default value of (2^22)-1 was chosen to be large enough to fit the log
	// of most Cilium programs, while falling just within the 5.1 maximum size in
	// one of the steps of the multiplication loop below. Without the -1, it would
	// overshoot the cap to 2^24, making e.g. verifier tests unable to load the
	// program if the previous size (2^22) was too small to fit the log.
	if opts.Programs.LogSize == 0 {
		opts.Programs.LogSize = 4_194_303
	}

	attempt := 1
	for {
		coll, err := ebpf.NewCollectionWithOptions(spec, opts)
		if err == nil {
			return coll, nil
		}

		// Bump LogSize and retry if there's a truncated VerifierError.
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) && ve.Truncated {
			if attempt >= 5 {
				return nil, fmt.Errorf("%d-byte truncated verifier log after %d attempts: %w", opts.Programs.LogSize, attempt, err)
			}

			// Retry with non-zero log level to avoid retrying with log disabled.
			if opts.Programs.LogLevel == 0 {
				opts.Programs.LogLevel = ebpf.LogLevelBranch
			}

			opts.Programs.LogSize *= 4

			attempt++

			continue
		}

		// Not a truncated VerifierError.
		return nil, err
	}
}

// classifyProgramTypes sets the type of ProgramSpecs which the library cannot
// automatically classify due to them being in unrecognized ELF sections. Only
// programs of type UnspecifiedProgram are modified.
//
// Cilium uses the iproute2 X/Y section name convention for assigning programs
// to prog array slots, which is also not supported.
//
// TODO(timo): When iproute2 is no longer used for any loading, tail call progs
// can receive proper prefixes.
func classifyProgramTypes(spec *ebpf.CollectionSpec) error {
	var t ebpf.ProgramType
	for name, p := range spec.Programs {
		// If the loader was able to classify a program, go with the verdict.
		if p.Type != ebpf.UnspecifiedProgram {
			t = p.Type
			break
		}

		// Assign a program type based on the first recognized function name.
		switch name {
		// bpf_xdp.c
		case "cil_xdp_entry":
			t = ebpf.XDP
		case
			// bpf_lxc.c
			"cil_from_container", "cil_to_container",
			// bpf_host.c
			"cil_from_netdev", "cil_from_host", "cil_to_netdev", "cil_to_host",
			// bpf_network.c
			"cil_from_network",
			// bpf_overlay.c
			"cil_to_overlay", "cil_from_overlay":
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

	if t == ebpf.UnspecifiedProgram {
		return errors.New("unable to classify program types")
	}

	return nil
}

// inlineGlobalData replaces all map loads from a global data section with
// immediate dword loads, effectively performing those map lookups in the
// loader. This is done for compatibility with kernels that don't support
// global data maps yet.
//
// This code interacts with the DECLARE_CONFIG macro in the BPF C code base.
func inlineGlobalData(spec *ebpf.CollectionSpec) error {
	vars, err := globalData(spec)
	if err != nil {
		return err
	}
	if vars == nil {
		// No static data, nothing to replace.
		return nil
	}

	for _, prog := range spec.Programs {
		for i, ins := range prog.Instructions {
			if !ins.IsLoadFromMap() || ins.Src != asm.PseudoMapValue {
				continue
			}

			if ins.Reference() != globalDataMap {
				return fmt.Errorf("global constants must be in %s, but found reference to %s", globalDataMap, ins.Reference())
			}

			// Get the offset of the read within the target map,
			// stored in the 32 most-significant bits of Constant.
			// Equivalent to Instruction.mapOffset().
			off := uint32(uint64(ins.Constant) >> 32)

			// Look up the value of the variable stored at the Datasec offset pointed
			// at by the instruction.
			value, ok := vars[off]
			if !ok {
				return fmt.Errorf("no global constant found in %s at offset %d", globalDataMap, off)
			}

			imm := spec.ByteOrder.Uint64(value)

			// Replace the map load with an immediate load. Must be a dword load
			// to match the instruction width of a map load.
			r := asm.LoadImm(ins.Dst, int64(imm), asm.DWord)

			// Preserve metadata of the original instruction. Otherwise, a program's
			// first instruction could be stripped of its func_info or Symbol
			// (function start) annotations.
			r.Metadata = ins.Metadata

			prog.Instructions[i] = r
		}
	}

	return nil
}

type varOffsets map[uint32][]byte

// globalData gets the contents of the first entry in the global data map
// and removes it from the spec to prevent it from being created in the kernel.
func globalData(spec *ebpf.CollectionSpec) (varOffsets, error) {
	dm := spec.Maps[globalDataMap]
	if dm == nil {
		return nil, nil
	}

	if dl := len(dm.Contents); dl != 1 {
		return nil, fmt.Errorf("expected one key in %s, found %d", globalDataMap, dl)
	}

	ds, ok := dm.Value.(*btf.Datasec)
	if !ok {
		return nil, fmt.Errorf("no BTF datasec found for %s", globalDataMap)
	}

	data, ok := (dm.Contents[0].Value).([]byte)
	if !ok {
		return nil, fmt.Errorf("expected %s value to be a byte slice, got: %T",
			globalDataMap, dm.Contents[0].Value)
	}

	// Slice up the binary contents of the global data map according to the
	// variables described in its Datasec.
	out := make(varOffsets)
	for _, vsi := range ds.Vars {
		if vsi.Size > 8 {
			return nil, fmt.Errorf("variables larger than 8 bytes are not supported (got %d)", vsi.Size)
		}

		if _, ok := out[vsi.Offset]; ok {
			return nil, fmt.Errorf("duplicate VarSecInfo for offset %d", vsi.Offset)
		}

		// Allocate a fixed slice of 8 bytes so it can be used to store in an imm64
		// instruction later using ByteOrder.Uint64().
		v := make([]byte, 8)
		copy(v, data[vsi.Offset:vsi.Offset+vsi.Size])

		// Emit the variable's value by its offset in the datasec.
		out[vsi.Offset] = v
	}

	// Remove the map definition to skip loading it into the kernel.
	delete(spec.Maps, globalDataMap)

	return out, nil
}
