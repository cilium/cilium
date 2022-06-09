package ebpf

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// splitSymbols splits insns into subsections delimited by Symbol Instructions.
// insns cannot be empty and must start with a Symbol Instruction.
//
// The resulting map is indexed by Symbol name.
func splitSymbols(insns asm.Instructions) (map[string]asm.Instructions, error) {
	if len(insns) == 0 {
		return nil, errors.New("insns is empty")
	}

	if insns[0].Symbol() == "" {
		return nil, errors.New("insns must start with a Symbol")
	}

	var name string
	progs := make(map[string]asm.Instructions)
	for _, ins := range insns {
		if sym := ins.Symbol(); sym != "" {
			if progs[sym] != nil {
				return nil, fmt.Errorf("insns contains duplicate Symbol %s", sym)
			}
			name = sym
		}

		progs[name] = append(progs[name], ins)
	}

	return progs, nil
}

// The linker is responsible for resolving bpf-to-bpf calls between programs
// within an ELF. Each BPF program must be a self-contained binary blob,
// so when an instruction in one ELF program section wants to jump to
// a function in another, the linker needs to pull in the bytecode
// (and BTF info) of the target function and concatenate the instruction
// streams.
//
// Later on in the pipeline, all call sites are fixed up with relative jumps
// within this newly-created instruction stream to then finally hand off to
// the kernel with BPF_PROG_LOAD.
//
// Each function is denoted by an ELF symbol and the compiler takes care of
// register setup before each jump instruction.

// populateReferences populates all of progs' Instructions and references
// with their full dependency chains including transient dependencies.
func populateReferences(progs map[string]*ProgramSpec) error {
	type props struct {
		insns asm.Instructions
		refs  map[string]*ProgramSpec
	}

	out := make(map[string]props)

	// Resolve and store direct references between all progs.
	if err := findReferences(progs); err != nil {
		return fmt.Errorf("finding references: %w", err)
	}

	// Flatten all progs' instruction streams.
	for name, prog := range progs {
		insns, refs := prog.flatten(nil)

		prop := props{
			insns: insns,
			refs:  refs,
		}

		out[name] = prop
	}

	// Replace all progs' instructions and references
	for name, props := range out {
		progs[name].Instructions = props.insns
		progs[name].references = props.refs
	}

	return nil
}

// findReferences finds bpf-to-bpf calls between progs and populates each
// prog's references field with its direct neighbours.
func findReferences(progs map[string]*ProgramSpec) error {
	// Check all ProgramSpecs in the collection against each other.
	for _, prog := range progs {
		prog.references = make(map[string]*ProgramSpec)

		// Look up call targets in progs and store pointers to their corresponding
		// ProgramSpecs as direct references.
		for refname := range prog.Instructions.FunctionReferences() {
			ref := progs[refname]
			// Call targets are allowed to be missing from an ELF. This occurs when
			// a program calls into a forward function declaration that is left
			// unimplemented. This is caught at load time during fixups.
			if ref != nil {
				prog.references[refname] = ref
			}
		}
	}

	return nil
}

// hasReferences returns true if insns contains one or more bpf2bpf
// function references.
func hasReferences(insns asm.Instructions) bool {
	for _, i := range insns {
		if i.IsFunctionReference() {
			return true
		}
	}
	return false
}

// applyRelocations collects and applies any CO-RE relocations in insns.
//
// Passing a nil target will relocate against the running kernel. insns are
// modified in place.
func applyRelocations(insns asm.Instructions, local, target *btf.Spec) error {
	var relos []*btf.CORERelocation
	var reloInsns []*asm.Instruction
	iter := insns.Iterate()
	for iter.Next() {
		if relo := btf.CORERelocationMetadata(iter.Ins); relo != nil {
			relos = append(relos, relo)
			reloInsns = append(reloInsns, iter.Ins)
		}
	}

	if len(relos) == 0 {
		return nil
	}

	target, err := maybeLoadKernelBTF(target)
	if err != nil {
		return err
	}

	fixups, err := btf.CORERelocate(local, target, relos)
	if err != nil {
		return err
	}

	for i, fixup := range fixups {
		if err := fixup.Apply(reloInsns[i]); err != nil {
			return fmt.Errorf("apply fixup %s: %w", &fixup, err)
		}
	}

	return nil
}

// fixupAndValidate is called by the ELF reader right before marshaling the
// instruction stream. It performs last-minute adjustments to the program and
// runs some sanity checks before sending it off to the kernel.
func fixupAndValidate(insns asm.Instructions) error {
	iter := insns.Iterate()
	for iter.Next() {
		ins := iter.Ins

		// Map load was tagged with a Reference, but does not contain a Map pointer.
		if ins.IsLoadFromMap() && ins.Reference() != "" && ins.Map() == nil {
			return fmt.Errorf("instruction %d: map %s: %w", iter.Index, ins.Reference(), asm.ErrUnsatisfiedMapReference)
		}

		fixupProbeReadKernel(ins)
	}

	return nil
}

// fixupProbeReadKernel replaces calls to bpf_probe_read_{kernel,user}(_str)
// with bpf_probe_read(_str) on kernels that don't support it yet.
func fixupProbeReadKernel(ins *asm.Instruction) {
	if !ins.IsBuiltinCall() {
		return
	}

	// Kernel supports bpf_probe_read_kernel, nothing to do.
	if haveProbeReadKernel() == nil {
		return
	}

	switch asm.BuiltinFunc(ins.Constant) {
	case asm.FnProbeReadKernel, asm.FnProbeReadUser:
		ins.Constant = int64(asm.FnProbeRead)
	case asm.FnProbeReadKernelStr, asm.FnProbeReadUserStr:
		ins.Constant = int64(asm.FnProbeReadStr)
	}
}

var kernelBTF struct {
	sync.Mutex
	spec *btf.Spec
}

// maybeLoadKernelBTF loads the current kernel's BTF if spec is nil, otherwise
// it returns spec unchanged.
//
// The kernel BTF is cached for the lifetime of the process.
func maybeLoadKernelBTF(spec *btf.Spec) (*btf.Spec, error) {
	if spec != nil {
		return spec, nil
	}

	kernelBTF.Lock()
	defer kernelBTF.Unlock()

	if kernelBTF.spec != nil {
		return kernelBTF.spec, nil
	}

	var err error
	kernelBTF.spec, err = btf.LoadKernelSpec()
	return kernelBTF.spec, err
}
