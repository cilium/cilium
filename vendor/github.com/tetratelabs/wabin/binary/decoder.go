package binary

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/tetratelabs/wabin/leb128"
	"github.com/tetratelabs/wabin/wasm"
)

// DecodeModule implements wasm.DecodeModule for the WebAssembly Binary Format
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-format%E2%91%A0
func DecodeModule(binary []byte, features wasm.CoreFeatures) (*wasm.Module, error) {
	r := bytes.NewReader(binary)

	// Magic number.
	buf := make([]byte, 4)
	if _, err := io.ReadFull(r, buf); err != nil || !bytes.Equal(buf, Magic) {
		return nil, ErrInvalidMagicNumber
	}

	// Version.
	if _, err := io.ReadFull(r, buf); err != nil || !bytes.Equal(buf, version) {
		return nil, ErrInvalidVersion
	}

	m := &wasm.Module{}
	for {
		// TODO: except custom sections, all others are required to be in order, but we aren't checking yet.
		// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#modules%E2%91%A0%E2%93%AA
		sectionID, err := r.ReadByte()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("read section id: %w", err)
		}

		sectionSize, _, err := leb128.DecodeUint32(r)
		if err != nil {
			return nil, fmt.Errorf("get size of section %s: %v", wasm.SectionIDName(sectionID), err)
		}

		sectionContentStart := r.Len()
		switch sectionID {
		case wasm.SectionIDCustom:
			// First, validate the section and determine if the section for this name has already been set
			name, nameSize, decodeErr := decodeUTF8(r, "custom section name")
			if decodeErr != nil {
				err = decodeErr
				break
			} else if sectionSize < nameSize {
				err = fmt.Errorf("malformed custom section %s", name)
				break
			} else if name == "name" && m.NameSection != nil {
				err = fmt.Errorf("redundant custom section %s", name)
				break
			}

			// Now, either decode the NameSection or CustomSection
			limit := sectionSize - nameSize
			if name == "name" {
				m.NameSection, err = decodeNameSection(r, uint64(limit))
			} else {
				custom, err := decodeCustomSection(r, name, uint64(limit))
				if err != nil {
					return nil, fmt.Errorf("failed to read custom section name[%s]: %w", name, err)
				}
				m.CustomSections = append(m.CustomSections, custom)
			}

		case wasm.SectionIDType:
			m.TypeSection, err = decodeTypeSection(features, r)
		case wasm.SectionIDImport:
			if m.ImportSection, err = decodeImportSection(r, features); err != nil {
				return nil, err // avoid re-wrapping the error.
			}
		case wasm.SectionIDFunction:
			m.FunctionSection, err = decodeFunctionSection(r)
		case wasm.SectionIDTable:
			m.TableSection, err = decodeTableSection(r, features)
		case wasm.SectionIDMemory:
			m.MemorySection, err = decodeMemorySection(r)
		case wasm.SectionIDGlobal:
			if m.GlobalSection, err = decodeGlobalSection(r, features); err != nil {
				return nil, err // avoid re-wrapping the error.
			}
		case wasm.SectionIDExport:
			m.ExportSection, err = decodeExportSection(r)
		case wasm.SectionIDStart:
			if m.StartSection != nil {
				return nil, errors.New("multiple start sections are invalid")
			}
			m.StartSection, err = decodeStartSection(r)
		case wasm.SectionIDElement:
			m.ElementSection, err = decodeElementSection(r, features)
		case wasm.SectionIDCode:
			m.CodeSection, err = decodeCodeSection(r)
		case wasm.SectionIDData:
			m.DataSection, err = decodeDataSection(r, features)
		case wasm.SectionIDDataCount:
			if err := features.RequireEnabled(wasm.CoreFeatureBulkMemoryOperations); err != nil {
				return nil, fmt.Errorf("data count section not supported as %v", err)
			}
			m.DataCountSection, err = decodeDataCountSection(r)
		default:
			err = ErrInvalidSectionID
		}

		readBytes := sectionContentStart - r.Len()
		if err == nil && int(sectionSize) != readBytes {
			err = fmt.Errorf("invalid section length: expected to be %d but got %d", sectionSize, readBytes)
		}

		if err != nil {
			return nil, fmt.Errorf("section %s: %v", wasm.SectionIDName(sectionID), err)
		}
	}

	functionCount, codeCount := m.SectionElementCount(wasm.SectionIDFunction), m.SectionElementCount(wasm.SectionIDCode)
	if functionCount != codeCount {
		return nil, fmt.Errorf("function and code section have inconsistent lengths: %d != %d", functionCount, codeCount)
	}
	return m, nil
}
