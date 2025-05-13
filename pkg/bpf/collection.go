// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"

	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	callsMap = "cilium_calls"
)

// LoadCollectionSpec loads the eBPF ELF at the given path and parses it into a
// CollectionSpec. This spec is only a blueprint of the contents of the ELF and
// does not represent any live resources that have been loaded into the kernel.
//
// This is a wrapper around ebpf.LoadCollectionSpec that populates the object's
// calls map with programs marked with the __declare_tail() annotation. It
// performs static reachability analysis of tail call programs. Any unreachable
// tail call program is removed from the spec.
func LoadCollectionSpec(logger *slog.Logger, path string) (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, err
	}

	if err := checkUnspecifiedPrograms(spec); err != nil {
		return nil, fmt.Errorf("checking for unspecified programs: %w", err)
	}

	if err := removeUnreachableTailcalls(logger, spec); err != nil {
		return nil, fmt.Errorf("removing unreachable tail calls: %w", err)
	}

	if err := resolveTailCalls(spec); err != nil {
		return nil, fmt.Errorf("resolving tail calls: %w", err)
	}

	return spec, nil
}

// checkUnspecifiedPrograms returns an error if any of the programs in the spec
// are of the UnspecifiedProgram type.
func checkUnspecifiedPrograms(spec *ebpf.CollectionSpec) error {
	for _, prog := range spec.Programs {
		if prog.Type == ebpf.UnspecifiedProgram {
			return fmt.Errorf("program %s has unspecified type: annotate with __section_entry or __declare_tail()", prog.Name)
		}
	}
	return nil
}

// isEntrypoint returns true if the program is marked with the __section_entry
// annotation.
func isEntrypoint(prog *ebpf.ProgramSpec) bool {
	return strings.HasSuffix(prog.SectionName, "/entry")
}

// isTailCall returns true if the program is marked with the __declare_tail()
// annotation.
func isTailCall(prog *ebpf.ProgramSpec) bool {
	return strings.HasSuffix(prog.SectionName, "/tail")
}

// tailCallSlot returns the tail call slot for the given program, which must be
// marked with the __declare_tail() annotation. The slot is the index in the
// calls map that the program will be called from.
func tailCallSlot(prog *ebpf.ProgramSpec) (uint32, error) {
	if !isTailCall(prog) {
		return 0, fmt.Errorf("program %s is not a tail call", prog.Name)
	}

	fn := btf.FuncMetadata(&prog.Instructions[0])
	if fn == nil {
		return 0, fmt.Errorf("program %s has no function metadata", prog.Name)
	}

	for _, tag := range fn.Tags {
		var slot uint32
		if _, err := fmt.Sscanf(tag, fmt.Sprintf("tail:%s/%%v", callsMap), &slot); err == nil {
			return slot, nil
		}
	}

	return 0, fmt.Errorf("program %s has no tail call slot", prog.Name)
}

// resolveTailCalls populates the calls map with Programs marked with the
// __declare_tail annotation.
func resolveTailCalls(spec *ebpf.CollectionSpec) error {
	// If cilium_calls map is missing, do nothing.
	ms := spec.Maps[callsMap]
	if ms == nil {
		return nil
	}

	if ms.Type != ebpf.ProgramArray {
		return fmt.Errorf("%s is not a program array, got %s", callsMap, ms.Type)
	}

	slots := make(map[uint32]struct{})
	for name, prog := range spec.Programs {
		if !isTailCall(prog) {
			continue
		}

		slot, err := tailCallSlot(prog)
		if err != nil {
			return fmt.Errorf("getting tail call slot: %w", err)
		}

		if _, ok := slots[slot]; ok {
			return fmt.Errorf("duplicate tail call slot %d", slot)
		}
		slots[slot] = struct{}{}

		ms.Contents = append(ms.Contents, ebpf.MapKV{Key: slot, Value: name})
	}

	return nil
}

// removeUnreachableTailcalls removes tail calls that are not reachable from
// entrypoint programs. This is done by traversing the call graph of the
// entrypoint programs and marking all reachable tail calls. Any tail call that
// is not marked is removed from the CollectionSpec.
func removeUnreachableTailcalls(logger *slog.Logger, spec *ebpf.CollectionSpec) error {
	type tail struct {
		referenced bool
		visited    bool
		spec       *ebpf.ProgramSpec
	}

	// Build a map of entrypoint programs annotated with __section_entry.
	entrypoints := make(map[string]*ebpf.ProgramSpec)
	for _, prog := range spec.Programs {
		if isEntrypoint(prog) {
			entrypoints[prog.Name] = prog
		}
	}

	// Build a map of tail call slots to ProgramSpecs.
	tailcalls := make(map[uint32]*tail)
	for _, prog := range spec.Programs {
		if !isTailCall(prog) {
			continue
		}

		slot, err := tailCallSlot(prog)
		if err != nil {
			return fmt.Errorf("getting tail call slot: %w", err)
		}

		tailcalls[slot] = &tail{
			spec: prog,
		}
	}

	// Discover all tailcalls that are reachable from the given program.
	visit := func(prog *ebpf.ProgramSpec, tailcalls map[uint32]*tail) error {
		// We look back from any tailcall, so we expect there to always be 3 instructions ahead of any tail call instr.
		for i := 3; i < len(prog.Instructions); i++ {
			// The `tail_call_static` C function is always used to call tail calls when
			// the map index is known at compile time.
			// Due to inline ASM this generates the following instructions:
			//   Mov R1, Rx
			//   Mov R2, <map>
			//   Mov R3, <index>
			//   call tail_call

			// Find the tail call instruction.
			inst := prog.Instructions[i]
			if !inst.IsBuiltinCall() || inst.Constant != int64(asm.FnTailCall) {
				continue
			}

			// Check that the previous instruction is a mov of the tail call index.
			movIdx := prog.Instructions[i-1]
			if movIdx.OpCode.ALUOp() != asm.Mov || movIdx.Dst != asm.R3 {
				continue
			}

			// Check that the instruction before that is the load of the tail call map.
			movR2 := prog.Instructions[i-2]
			if movR2.OpCode != asm.LoadImmOp(asm.DWord) || movR2.Src != asm.PseudoMapFD {
				continue
			}

			ref := movR2.Reference()

			// Ignore static tail calls made to maps that are not the calls map
			if ref != callsMap {
				logger.Debug(
					"skipping tail call into map other than the calls map",
					logfields.Section, prog.SectionName,
					logfields.Prog, prog.Name,
					logfields.Instruction, i,
					logfields.Reference, ref,
				)
				continue
			}

			tc := tailcalls[uint32(movIdx.Constant)]
			if tc == nil {
				return fmt.Errorf(
					"potential missed tail call in program %s to slot %d at insn %d",
					prog.Name,
					movIdx.Constant,
					i,
				)
			}

			tc.referenced = true
		}

		return nil
	}

	// Discover all tailcalls that are reachable from the entrypoints.
	for _, prog := range entrypoints {
		if err := visit(prog, tailcalls); err != nil {
			return err
		}
	}

	// Keep visiting tailcalls until no more are discovered.
reset:
	for _, tailcall := range tailcalls {
		// If a tailcall is referenced by an entrypoint or another tailcall we should visit it
		if tailcall.referenced && !tailcall.visited {
			if err := visit(tailcall.spec, tailcalls); err != nil {
				return err
			}
			tailcall.visited = true

			// Visiting this tail call might have caused tail calls earlier in the list to become referenced, but this
			// loop already skipped them. So reset the loop. If we already visited a tailcall we will ignore them anyway.
			goto reset
		}
	}

	// Remove all tailcalls that are not referenced.
	for _, tailcall := range tailcalls {
		if !tailcall.referenced {
			logger.Debug(
				"unreferenced tail call, deleting",
				logfields.Section, tailcall.spec.SectionName,
				logfields.Prog, tailcall.spec.Name,
			)

			delete(spec.Programs, tailcall.spec.Name)
		}
	}

	return nil
}

// LoadAndAssign loads spec into the kernel and assigns the requested eBPF
// objects to the given object. It is a wrapper around [LoadCollection]. See its
// documentation for more details on the loading process.
func LoadAndAssign(logger *slog.Logger, to any, spec *ebpf.CollectionSpec, opts *CollectionOptions) (func() error, error) {
	coll, commit, err := LoadCollection(logger, spec, opts)
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		if _, err := fmt.Fprintf(os.Stderr, "Verifier error: %s\nVerifier log: %+v\n", err, ve); err != nil {
			return nil, fmt.Errorf("writing verifier log to stderr: %w", err)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("loading eBPF collection into the kernel: %w", err)
	}

	if err := coll.Assign(to); err != nil {
		return nil, fmt.Errorf("assigning eBPF objects to %T: %w", to, err)
	}

	return commit, nil
}

type CollectionOptions struct {
	ebpf.CollectionOptions

	// Replacements for datapath runtime configs declared using DECLARE_CONFIG.
	// Pass a pointer to a populated object from pkg/datapath/config.
	Constants any

	// Maps to be renamed during loading. Key is the key in CollectionSpec.Maps,
	// value is the new name.
	MapRenames map[string]string
}

// LoadCollection loads the given spec into the kernel with the specified opts.
// Returns a function that must be called after the Collection's entrypoints are
// attached to their respective kernel hooks. This function commits pending map
// pins to the bpf file system for maps that were found to be incompatible with
// their pinned counterparts, or for maps with certain flags that modify the
// default pinning behaviour.
//
// When attaching multiple programs from the same ELF in a loop, the returned
// function should only be run after all entrypoints have been attached. For
// example, attach both bpf_host.c:cil_to_netdev and cil_from_netdev before
// invoking the returned function, otherwise missing tail calls will occur.
//
// The value given in ProgramOptions.LogSize is used as the starting point for
// sizing the verifier's log buffer and defaults to 4MiB. On each retry, the log
// buffer quadruples in size, for a total of 5 attempts. If that proves
// insufficient, a truncated ebpf.VerifierError is returned.
//
// Any maps marked as pinned in the spec are automatically loaded from the path
// given in opts.Maps.PinPath and will be used instead of creating new ones.
func LoadCollection(logger *slog.Logger, spec *ebpf.CollectionSpec, opts *CollectionOptions) (*ebpf.Collection, func() error, error) {
	if spec == nil {
		return nil, nil, errors.New("can't load nil CollectionSpec")
	}

	if opts == nil {
		opts = &CollectionOptions{}
	}

	logger.Debug("Loading Collection into kernel",
		logfields.MapRenames, opts.MapRenames,
		logfields.Constants, fmt.Sprintf("%#v", opts.Constants),
	)

	// Copy spec so the modifications below don't affect the input parameter,
	// allowing the spec to be safely re-used by the caller.
	spec = spec.Copy()

	if err := renameMaps(spec, opts.MapRenames); err != nil {
		return nil, nil, err
	}

	if err := applyConstants(spec, opts.Constants); err != nil {
		return nil, nil, fmt.Errorf("applying variable overrides: %w", err)
	}

	// Find and strip all CILIUM_PIN_REPLACE pinning flags before creating the
	// Collection. ebpf-go will reject maps with pins it doesn't recognize.
	toReplace := consumePinReplace(spec)

	// Attempt to load the Collection.
	coll, err := ebpf.NewCollectionWithOptions(spec, opts.CollectionOptions)

	// Collect key names of maps that are not compatible with their pinned
	// counterparts and remove their pinning flags.
	if errors.Is(err, ebpf.ErrMapIncompatible) {
		var incompatible []string
		incompatible, err = incompatibleMaps(spec, opts.CollectionOptions)
		if err != nil {
			return nil, nil, fmt.Errorf("finding incompatible maps: %w", err)
		}
		toReplace = append(toReplace, incompatible...)

		// Retry loading the Collection with necessary pinning flags removed.
		coll, err = ebpf.NewCollectionWithOptions(spec, opts.CollectionOptions)
	}

	if err != nil {
		return nil, nil, err
	}

	// Collect Maps that need their bpffs pins replaced. Pull out Map objects
	// before returning the Collection, since commit() still needs to work when
	// the Map is removed from the Collection, e.g. by [ebpf.Collection.Assign].
	pins, err := mapsToReplace(toReplace, spec, coll, opts.CollectionOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("collecting map pins to replace: %w", err)
	}

	// Load successful, return a function that must be invoked after attaching the
	// Collection's entrypoint programs to their respective hooks.
	commit := func() error {
		return commitMapPins(logger, pins)
	}
	return coll, commit, nil
}

// renameMaps applies renames to coll.
func renameMaps(coll *ebpf.CollectionSpec, renames map[string]string) error {
	for name, rename := range renames {
		mapSpec := coll.Maps[name]
		if mapSpec == nil {
			return fmt.Errorf("unknown map %q: can't rename to %q", name, rename)
		}

		mapSpec.Name = rename
	}

	return nil
}

// applyConstants sets the values of BPF C runtime configurables defined using
// the DECLARE_CONFIG macro.
func applyConstants(spec *ebpf.CollectionSpec, obj any) error {
	if obj == nil {
		return nil
	}

	constants, err := config.StructToMap(obj)
	if err != nil {
		return fmt.Errorf("converting struct to map: %w", err)
	}

	for name, value := range constants {
		constName := config.ConstantPrefix + name

		v, ok := spec.Variables[constName]
		if !ok {
			return fmt.Errorf("can't set non-existent Variable %s", name)
		}

		if v.MapName() != config.Section {
			return fmt.Errorf("can only set Cilium config variables in section %s (got %s:%s), ", config.Section, v.MapName(), name)
		}

		if err := v.Set(value); err != nil {
			return fmt.Errorf("setting Variable %s: %w", name, err)
		}
	}

	return nil
}
