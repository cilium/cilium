// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package fieldmask

import (
	"fmt"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

type FieldMask map[string]FieldMask

// New constructs a tree filter based on validated and normalized field
// mask fm. Use Active() to check if applying a filter will have any effect.
func New(fm *fieldmaskpb.FieldMask) (FieldMask, error) {
	if fm == nil {
		return nil, nil
	}
	if !fm.IsValid(&flowpb.Flow{}) {
		return nil, fmt.Errorf("invalid fieldmask")
	}
	fm.Normalize()

	f := make(FieldMask)
	for _, path := range fm.GetPaths() {
		f.add(path)
	}
	return f, nil
}

// add recursively converts path into tree based on its dot separated
// components.
func (f FieldMask) add(path string) {
	prefix, suffix, found := strings.Cut(path, ".")
	if !found {
		// ["src.id", "src"] doesn't occur due to fm.Normalize()
		f[path] = nil
		return
	}
	if m, ok := f[prefix]; !ok || m == nil {
		f[prefix] = make(FieldMask)
	}
	f[prefix].add(suffix)
}

// Copy sets fields in dst to values from src based on filter.
// It has no effect when called on an empty filter (dst remains unchanged).
func (f FieldMask) Copy(dst, src protoreflect.Message) {
	fds := dst.Descriptor().Fields()
	for name, next := range f {
		fd := fds.ByName(protoreflect.Name(name))
		if len(next) == 0 {
			// Leaf node - copy the field value directly.
			if src.Has(fd) {
				dst.Set(fd, src.Get(fd))
			} else {
				dst.Clear(fd)
			}
		} else {
			// Has sub-fields - need to recursively copy.
			// Recursion is bounded by the protobuf schema depth (typically 2-4 levels for Flow messages).
			// Check if this field is part of a oneof (e.g., Layer4.Protocol can be TCP, UDP, SCTP, or ICMPv4/v6).
			if fd.ContainingOneof() != nil {
				// This field is part of a oneof group.
				// Only copy if this variant is actually set in the source.
				whichOneof := src.WhichOneof(fd.ContainingOneof())

				if whichOneof != nil && whichOneof.Name() == fd.Name() {
					// This is the active oneof variant in source - copy it.
					if sub := dst.Get(fd); sub.Message().IsValid() {
						next.Copy(sub.Message(), src.Get(fd).Message())
					} else {
						next.Copy(dst.Mutable(fd).Message(), src.Get(fd).Message())
					}
				}
				// If not the active variant, skip it (don't create spurious structures).
			} else {
				// Not a oneof field - copy normally.
				if sub := dst.Get(fd); sub.Message().IsValid() {
					next.Copy(sub.Message(), src.Get(fd).Message())
				} else {
					next.Copy(dst.Mutable(fd).Message(), src.Get(fd).Message())
				}
			}
		}
	}
}

// Alloc creates all nested protoreflect.Message fields to avoid allocation later.
func (f FieldMask) Alloc(src protoreflect.Message) {
	fds := src.Descriptor().Fields()
	for i := range fds.Len() {
		fd := fds.Get(i)
		if next, ok := f[string(fd.Name())]; ok {
			if len(next) > 0 {
				// Call to Mutable allocates a composite value - protoreflect.Message in this case.
				// See: https://pkg.go.dev/google.golang.org/protobuf/reflect/protoreflect#Message
				next.Alloc(src.Mutable(fd).Message())
			}
		}
	}
}

// Active checks if applying a filter will have any effect.
func (f FieldMask) Active() bool {
	return len(f) > 0
}
