package binary

import (
	"bytes"
	"fmt"
	"io"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/internal/leb128"
	"github.com/tetratelabs/wazero/internal/wasm"
)

func decodeTypeSection(enabledFeatures api.CoreFeatures, r *bytes.Reader) ([]wasm.FunctionType, error) {
	vs, _, err := leb128.DecodeUint32(r)
	if err != nil {
		return nil, fmt.Errorf("get size of vector: %w", err)
	}

	var result []wasm.FunctionType
	for i := uint32(0); i < vs; i++ {
		// Peek at the leading byte to check for rec group (0x4e, GC proposal).
		b, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("read %d-th type: %v", i, err)
		}
		if b == 0x4e {
			// Rec group: contains multiple types.
			recCount, _, err := leb128.DecodeUint32(r)
			if err != nil {
				return nil, fmt.Errorf("read rec group count: %v", err)
			}
			startIdx := uint32(len(result))
			for j := uint32(0); j < recCount; j++ {
				var ft wasm.FunctionType
				if err = decodeFunctionType(enabledFeatures, r, &ft); err != nil {
					return nil, fmt.Errorf("read %d-th type in rec group: %v", j, err)
				}
				ft.RecGroupSize = int(recCount)
				ft.RecGroupPosition = int(j)
				result = append(result, ft)
			}
			for j := uint32(0); j < recCount; j++ {
				if err := validateTypeForwardRefs(&result[startIdx+j], startIdx+recCount); err != nil {
					return nil, err
				}
			}
		} else {
			// Put back the byte and decode as a regular function type.
			if err := r.UnreadByte(); err != nil {
				return nil, err
			}
			var ft wasm.FunctionType
			if err = decodeFunctionType(enabledFeatures, r, &ft); err != nil {
				return nil, fmt.Errorf("read %d-th type: %v", i, err)
			}
			if err := validateTypeForwardRefs(&ft, uint32(len(result))); err != nil {
				return nil, err
			}
			result = append(result, ft)
		}
	}
	return result, nil
}

// validateTypeForwardRefs rejects concrete reference types (ref $t) whose type
// index is not yet defined. For standalone types, maxTypeIndex is the count of
// types decoded so far; for rec groups, it is the index after the last member,
// allowing mutual references within the group.
func validateTypeForwardRefs(ft *wasm.FunctionType, maxTypeIndex uint32) error {
	for i, vt := range ft.Params {
		if vt.IsConcreteRef() && vt.TypeIndex() >= maxTypeIndex {
			return fmt.Errorf("unknown type index %d in param[%d]", vt.TypeIndex(), i)
		}
	}
	for i, vt := range ft.Results {
		if vt.IsConcreteRef() && vt.TypeIndex() >= maxTypeIndex {
			return fmt.Errorf("unknown type index %d in result[%d]", vt.TypeIndex(), i)
		}
	}
	return nil
}

// decodeImportSection decodes the decoded import segments plus the count per wasm.ExternType.
func decodeImportSection(
	r *bytes.Reader,
	memorySizer memorySizer,
	memoryLimitPages uint32,
	enabledFeatures api.CoreFeatures,
) (result []wasm.Import,
	perModule map[string][]*wasm.Import,
	funcCount, globalCount, memoryCount, tableCount, tagCount wasm.Index, err error,
) {
	vs, _, err := leb128.DecodeUint32(r)
	if err != nil {
		err = fmt.Errorf("get size of vector: %w", err)
		return
	}

	perModule = make(map[string][]*wasm.Import)
	result = make([]wasm.Import, vs)
	for i := uint32(0); i < vs; i++ {
		imp := &result[i]
		if err = decodeImport(r, i, memorySizer, memoryLimitPages, enabledFeatures, imp); err != nil {
			return
		}
		switch imp.Type {
		case wasm.ExternTypeFunc:
			imp.IndexPerType = funcCount
			funcCount++
		case wasm.ExternTypeGlobal:
			imp.IndexPerType = globalCount
			globalCount++
		case wasm.ExternTypeMemory:
			imp.IndexPerType = memoryCount
			memoryCount++
		case wasm.ExternTypeTable:
			imp.IndexPerType = tableCount
			tableCount++
		case wasm.ExternTypeTag:
			imp.IndexPerType = tagCount
			tagCount++
		}
		perModule[imp.Module] = append(perModule[imp.Module], imp)
	}
	return
}

func decodeFunctionSection(r *bytes.Reader) ([]uint32, error) {
	vs, _, err := leb128.DecodeUint32(r)
	if err != nil {
		return nil, fmt.Errorf("get size of vector: %w", err)
	}

	result := make([]uint32, vs)
	for i := uint32(0); i < vs; i++ {
		if result[i], _, err = leb128.DecodeUint32(r); err != nil {
			return nil, fmt.Errorf("get type index: %w", err)
		}
	}
	return result, err
}

func decodeTableSection(r *bytes.Reader, enabledFeatures api.CoreFeatures) ([]wasm.Table, error) {
	vs, _, err := leb128.DecodeUint32(r)
	if err != nil {
		return nil, fmt.Errorf("error reading size")
	}
	if vs > 1 {
		if err := enabledFeatures.RequireEnabled(api.CoreFeatureReferenceTypes); err != nil {
			return nil, fmt.Errorf("at most one table allowed in module as %w", err)
		}
	}

	ret := make([]wasm.Table, vs)
	for i := range ret {
		err = decodeTable(r, enabledFeatures, &ret[i])
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

func decodeMemorySection(
	r *bytes.Reader,
	enabledFeatures api.CoreFeatures,
	memorySizer memorySizer,
	memoryLimitPages uint32,
) (*wasm.Memory, error) {
	vs, _, err := leb128.DecodeUint32(r)
	if err != nil {
		return nil, fmt.Errorf("error reading size")
	}
	if vs > 1 {
		return nil, fmt.Errorf("at most one memory allowed in module, but read %d", vs)
	} else if vs == 0 {
		// memory count can be zero.
		return nil, nil
	}

	return decodeMemory(r, enabledFeatures, memorySizer, memoryLimitPages)
}

func decodeGlobalSection(r *bytes.Reader, enabledFeatures api.CoreFeatures) ([]wasm.Global, error) {
	vs, _, err := leb128.DecodeUint32(r)
	if err != nil {
		return nil, fmt.Errorf("get size of vector: %w", err)
	}

	result := make([]wasm.Global, vs)
	for i := uint32(0); i < vs; i++ {
		if err = decodeGlobal(r, enabledFeatures, &result[i]); err != nil {
			return nil, fmt.Errorf("global[%d]: %w", i, err)
		}
	}
	return result, nil
}

func decodeExportSection(r *bytes.Reader) ([]wasm.Export, map[string]*wasm.Export, error) {
	vs, _, sizeErr := leb128.DecodeUint32(r)
	if sizeErr != nil {
		return nil, nil, fmt.Errorf("get size of vector: %v", sizeErr)
	}

	exportMap := make(map[string]*wasm.Export, vs)
	exportSection := make([]wasm.Export, vs)
	for i := wasm.Index(0); i < vs; i++ {
		export := &exportSection[i]
		err := decodeExport(r, export)
		if err != nil {
			return nil, nil, fmt.Errorf("read export: %w", err)
		}
		if _, ok := exportMap[export.Name]; ok {
			return nil, nil, fmt.Errorf("export[%d] duplicates name %q", i, export.Name)
		} else {
			exportMap[export.Name] = export
		}
	}
	return exportSection, exportMap, nil
}

func decodeStartSection(r *bytes.Reader) (*wasm.Index, error) {
	vs, _, err := leb128.DecodeUint32(r)
	if err != nil {
		return nil, fmt.Errorf("get function index: %w", err)
	}
	return &vs, nil
}

func decodeElementSection(r *bytes.Reader, enabledFeatures api.CoreFeatures) ([]wasm.ElementSegment, error) {
	vs, _, err := leb128.DecodeUint32(r)
	if err != nil {
		return nil, fmt.Errorf("get size of vector: %w", err)
	}

	result := make([]wasm.ElementSegment, vs)
	for i := uint32(0); i < vs; i++ {
		if err = decodeElementSegment(r, enabledFeatures, &result[i]); err != nil {
			return nil, fmt.Errorf("read element: %w", err)
		}
	}
	return result, nil
}

func decodeCodeSection(r *bytes.Reader) ([]wasm.Code, error) {
	codeSectionStart := uint64(r.Len())
	vs, _, err := leb128.DecodeUint32(r)
	if err != nil {
		return nil, fmt.Errorf("get size of vector: %w", err)
	}

	result := make([]wasm.Code, vs)
	for i := uint32(0); i < vs; i++ {
		err = decodeCode(r, codeSectionStart, &result[i])
		if err != nil {
			return nil, fmt.Errorf("read %d-th code segment: %v", i, err)
		}
	}
	return result, nil
}

func decodeDataSection(r *bytes.Reader, enabledFeatures api.CoreFeatures) ([]wasm.DataSegment, error) {
	vs, _, err := leb128.DecodeUint32(r)
	if err != nil {
		return nil, fmt.Errorf("get size of vector: %w", err)
	}

	result := make([]wasm.DataSegment, vs)
	for i := uint32(0); i < vs; i++ {
		if err = decodeDataSegment(r, enabledFeatures, &result[i]); err != nil {
			return nil, fmt.Errorf("read data segment: %w", err)
		}
	}
	return result, nil
}

func decodeTagSection(r *bytes.Reader) ([]wasm.Tag, error) {
	vs, _, err := leb128.DecodeUint32(r)
	if err != nil {
		return nil, fmt.Errorf("get size of vector: %w", err)
	}

	result := make([]wasm.Tag, vs)
	for i := uint32(0); i < vs; i++ {
		// Read attribute byte (must be 0x00 per spec).
		attr, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("read tag[%d] attribute: %w", i, err)
		}
		if attr != 0x00 {
			return nil, fmt.Errorf("tag[%d] has invalid attribute: %#x", i, attr)
		}
		// Read type index.
		result[i].Type, _, err = leb128.DecodeUint32(r)
		if err != nil {
			return nil, fmt.Errorf("read tag[%d] type index: %w", i, err)
		}
	}
	return result, nil
}

func decodeDataCountSection(r *bytes.Reader) (count *uint32, err error) {
	v, _, err := leb128.DecodeUint32(r)
	if err != nil && err != io.EOF {
		// data count is optional, so EOF is fine.
		return nil, err
	}
	return &v, nil
}
