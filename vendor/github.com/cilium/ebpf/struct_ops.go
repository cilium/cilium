package ebpf

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
)

const structOpsValuePrefix = "bpf_struct_ops_"

// structOpsFindInnerType returns the "inner" struct inside a value struct_ops type.
//
// Given a value like:
//
//	struct bpf_struct_ops_bpf_testmod_ops {
//	    struct bpf_struct_ops_common common;
//	    struct bpf_testmod_ops data;
//	};
//
// this function returns the *btf.Struct for "bpf_testmod_ops" along with the
// byte offset of the "data" member inside the value type.
//
// The inner struct name is derived by trimming the "bpf_struct_ops_" prefix
// from the value's name.
func structOpsFindInnerType(vType *btf.Struct) (*btf.Struct, uint32, error) {
	innerName := strings.TrimPrefix(vType.Name, structOpsValuePrefix)

	for _, m := range vType.Members {
		if st, ok := btf.As[*btf.Struct](m.Type); ok && st.Name == innerName {
			return st, m.Offset.Bytes(), nil
		}
	}

	return nil, 0, fmt.Errorf("inner struct %q not found in %s", innerName, vType.Name)
}

// structOpsFindTarget resolves the kernel-side "value struct" for a struct_ops map.
func structOpsFindTarget(userType *btf.Struct, cache *btf.Cache) (vType *btf.Struct, id btf.TypeID, module *btf.Handle, err error) {
	// the kernel value type name, e.g. "bpf_struct_ops_<name>"
	vTypeName := structOpsValuePrefix + userType.Name

	target := btf.Type((*btf.Struct)(nil))
	spec, module, err := findTargetInKernel(vTypeName, &target, cache)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("lookup value type %q: %w", vTypeName, err)
	}

	id, err = spec.TypeID(target)
	if err != nil {
		return nil, 0, nil, err
	}

	return target.(*btf.Struct), id, module, nil
}

// structOpsPopulateValue writes a `prog FD` which references to `p` into the
// struct_ops value buffer `kernVData` at byte offset `dstOff` corresponding to
// the member `km`.
func structOpsPopulateValue(km btf.Member, kernVData []byte, p *Program) error {
	kmPtr, ok := btf.As[*btf.Pointer](km.Type)
	if !ok {
		return fmt.Errorf("member %s is not a func pointer", km.Name)
	}

	if _, isFuncProto := btf.As[*btf.FuncProto](kmPtr.Target); !isFuncProto {
		return fmt.Errorf("member %s is not a func pointer", km.Name)
	}

	dstOff := int(km.Offset.Bytes())
	if dstOff < 0 || dstOff+8 > len(kernVData) {
		return fmt.Errorf("member %q: value buffer too small for func ptr", km.Name)
	}

	internal.NativeEndian.PutUint64(kernVData[dstOff:dstOff+8], uint64(p.FD()))
	return nil
}

// structOpsCopyMember copies a single member from the user struct (m)
// into the kernel value struct (km) for struct_ops.
func structOpsCopyMember(m, km btf.Member, data []byte, kernVData []byte) error {
	mSize, err := btf.Sizeof(m.Type)
	if err != nil {
		return fmt.Errorf("sizeof(user.%s): %w", m.Name, err)
	}
	kSize, err := btf.Sizeof(km.Type)
	if err != nil {
		return fmt.Errorf("sizeof(kernel.%s): %w", km.Name, err)
	}
	if mSize != kSize {
		return fmt.Errorf("size mismatch for %s: user=%d kernel=%d", m.Name, mSize, kSize)
	}
	if km.BitfieldSize > 0 || m.BitfieldSize > 0 {
		return fmt.Errorf("bitfield %s not supported", m.Name)
	}

	srcOff := int(m.Offset.Bytes())
	dstOff := int(km.Offset.Bytes())

	if srcOff < 0 || srcOff+mSize > len(data) {
		return fmt.Errorf("member %q: userdata is too small", m.Name)
	}

	if dstOff < 0 || dstOff+mSize > len(kernVData) {
		return fmt.Errorf("member %q: value type is too small", m.Name)
	}

	// skip mods(const, restrict, volatile and typetag)
	// and typedef to check type compatibility
	mType := btf.UnderlyingType(m.Type)
	kernMType := btf.UnderlyingType(km.Type)
	if reflect.TypeOf(mType) != reflect.TypeOf(kernMType) {
		return fmt.Errorf("unmatched member type %s != %s (kernel)", m.Name, km.Name)
	}

	switch mType.(type) {
	case *btf.Struct, *btf.Union:
		if !structOpsIsMemZeroed(data[srcOff : srcOff+mSize]) {
			return fmt.Errorf("non-zero nested struct %s: %w", m.Name, ErrNotSupported)
		}
		// the bytes has zeroed value, we simply skip the copy.
		return nil
	}

	copy(kernVData[dstOff:dstOff+mSize], data[srcOff:srcOff+mSize])
	return nil
}

// structOpsIsMemZeroed() checks whether all bytes in data are zero.
func structOpsIsMemZeroed(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
