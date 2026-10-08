// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package registry

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

// MapSpecPatch allows modifying select fields of an [ebpf.MapSpec].
type MapSpecPatch struct {
	MaxEntries uint32
	Flags      uint32

	InnerMap *MapSpecPatch
}

func newMapSpecPatch(spec *ebpf.MapSpec) *MapSpecPatch {
	if spec == nil {
		return nil
	}

	return &MapSpecPatch{
		MaxEntries: spec.MaxEntries,
		Flags:      spec.Flags,
		InnerMap:   newMapSpecPatch(spec.InnerMap),
	}
}

// diff returns a human-readable description of the differences between
// this patch and the given new patch. Returns an empty string if there are
// no differences.
func (p *MapSpecPatch) diff(new *MapSpecPatch) string {
	if new == nil {
		return ""
	}

	var diffs []string
	if p.MaxEntries != new.MaxEntries {
		diffs = append(diffs, fmt.Sprintf("MaxEntries: %d -> %d", p.MaxEntries, new.MaxEntries))
	}
	if p.Flags != new.Flags {
		diffs = append(diffs, fmt.Sprintf("Flags: %d -> %d", p.Flags, new.Flags))
	}

	if inner := p.InnerMap.diff(new.InnerMap); inner != "" {
		diffs = append(diffs, fmt.Sprintf("InnerMap: {%s}", inner))
	}

	return strings.Join(diffs, ", ")
}

// Apply applies the patch to the given MapSpec.
func (p *MapSpecPatch) Apply(spec *ebpf.MapSpec) {
	spec.MaxEntries = p.MaxEntries
	spec.Flags = p.Flags

	if spec.InnerMap != nil && p.InnerMap != nil {
		p.InnerMap.Apply(spec.InnerMap)
	}
}

// copy returns a deep copy of p.
func (p *MapSpecPatch) copy() *MapSpecPatch {
	if p == nil {
		return nil
	}

	return &MapSpecPatch{
		MaxEntries: p.MaxEntries,
		Flags:      p.Flags,
		InnerMap:   p.InnerMap.copy(),
	}
}
