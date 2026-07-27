// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf/analyze"
)

type reachableSpec struct {
	*ebpf.ProgramSpec
	*analyze.Reachable
}

type reachables map[string]*reachableSpec

func computeReachability(spec *ebpf.CollectionSpec) (reachables, error) {
	out := make(reachables, len(spec.Programs))

	for name, prog := range spec.Programs {
		// Load Blocks computed after compilation, or compute new ones.
		bl, err := analyze.MakeBlocks(prog.Instructions)
		if err != nil {
			return nil, fmt.Errorf("computing Blocks for Program %s: %w", prog.Name, err)
		}

		// Analyze reachability given the VariableSpecs provided at load time.
		r, err := analyze.Reachability(bl, prog.Instructions, spec.Variables)
		if err != nil {
			return nil, fmt.Errorf("reachability analysis for program %s: %w", prog.Name, err)
		}
		out[name] = &reachableSpec{prog, r}
	}

	return out, nil
}
