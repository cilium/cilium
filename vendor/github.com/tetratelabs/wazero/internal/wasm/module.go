package wasm

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/wasmdebug"
)

// Module is a WebAssembly binary representation.
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#modules%E2%91%A8
//
// Differences from the specification:
// * NameSection is the only key ("name") decoded from the SectionIDCustom.
// * ExportSection is represented as a map for lookup convenience.
// * Code.GoFunc is contains any go `func`. It may be present when Code.Body is not.
type Module struct {
	// TypeSection contains the unique FunctionType of functions imported or defined in this module.
	//
	// Note: Currently, there is no type ambiguity in the index as WebAssembly 1.0 only defines function type.
	// In the future, other types may be introduced to support CoreFeatures such as module linking.
	//
	// Note: In the Binary Format, this is SectionIDType.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#types%E2%91%A0%E2%91%A0
	TypeSection []FunctionType

	// ImportSection contains imported functions, tables, memories or globals required for instantiation
	// (Store.Instantiate).
	//
	// Note: there are no unique constraints relating to the two-level namespace of Import.Module and Import.Name.
	//
	// Note: In the Binary Format, this is SectionIDImport.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#import-section%E2%91%A0
	ImportSection []Import
	// ImportFunctionCount ImportGlobalCount ImportMemoryCount, and ImportTableCount are
	// the cached import count per ExternType set during decoding.
	ImportFunctionCount,
	ImportGlobalCount,
	ImportMemoryCount,
	ImportTableCount Index
	// ImportPerModule maps a module name to the list of Import to be imported from the module.
	// This is used to do fast import resolution during instantiation.
	ImportPerModule map[string][]*Import

	// FunctionSection contains the index in TypeSection of each function defined in this module.
	//
	// Note: The function Index space begins with imported functions and ends with those defined in this module.
	// For example, if there are two imported functions and one defined in this module, the function Index 3 is defined
	// in this module at FunctionSection[0].
	//
	// Note: FunctionSection is index correlated with the CodeSection. If given the same position, e.g. 2, a function
	// type is at TypeSection[FunctionSection[2]], while its locals and body are at CodeSection[2].
	//
	// Note: In the Binary Format, this is SectionIDFunction.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#function-section%E2%91%A0
	FunctionSection []Index

	// TableSection contains each table defined in this module.
	//
	// Note: The table Index space begins with imported tables and ends with those defined in this module.
	// For example, if there are two imported tables and one defined in this module, the table Index 3 is defined in
	// this module at TableSection[0].
	//
	// Note: Version 1.0 (20191205) of the WebAssembly spec allows at most one table definition per module, so the
	// length of the TableSection can be zero or one, and can only be one if there is no imported table.
	//
	// Note: In the Binary Format, this is SectionIDTable.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#table-section%E2%91%A0
	TableSection []Table

	// MemorySection contains each memory defined in this module.
	//
	// Note: The memory Index space begins with imported memories and ends with those defined in this module.
	// For example, if there are two imported memories and one defined in this module, the memory Index 3 is defined in
	// this module at TableSection[0].
	//
	// Note: Version 1.0 (20191205) of the WebAssembly spec allows at most one memory definition per module, so the
	// length of the MemorySection can be zero or one, and can only be one if there is no imported memory.
	//
	// Note: In the Binary Format, this is SectionIDMemory.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#memory-section%E2%91%A0
	MemorySection *Memory

	// TagSection contains each tag defined in this module for exception handling.
	//
	// Tag indexes are offset by any imported tags because the tag index begins with imports, followed by
	// ones defined in this module.
	//
	// Note: In the Binary Format, this is SectionIDTag.
	//
	// See https://github.com/WebAssembly/exception-handling/blob/main/proposals/exception-handling/Exceptions.md
	TagSection []Tag

	// ImportTagCount is the cached count of imported tags set during decoding.
	ImportTagCount Index

	// GlobalSection contains each global defined in this module.
	//
	// Global indexes are offset by any imported globals because the global index begins with imports, followed by
	// ones defined in this module. For example, if there are two imported globals and three defined in this module, the
	// global at index 3 is defined in this module at GlobalSection[0].
	//
	// Note: In the Binary Format, this is SectionIDGlobal.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#global-section%E2%91%A0
	GlobalSection []Global

	// ExportSection contains each export defined in this module.
	//
	// Note: In the Binary Format, this is SectionIDExport.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#exports%E2%91%A0
	ExportSection []Export
	// Exports maps a name to Export, and is convenient for fast look up of exported instances at runtime.
	// Each item of this map points to an element of ExportSection.
	Exports map[string]*Export

	// StartSection is the index of a function to call before returning from Store.Instantiate.
	//
	// Note: The index here is not the position in the FunctionSection, rather in the function index, which
	// begins with imported functions.
	//
	// Note: In the Binary Format, this is SectionIDStart.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#start-section%E2%91%A0
	StartSection *Index

	// Note: In the Binary Format, this is SectionIDElement.
	ElementSection []ElementSegment

	// CodeSection is index-correlated with FunctionSection and contains each
	// function's locals and body.
	//
	// When present, the HostFunctionSection of the same index must be nil.
	//
	// Note: In the Binary Format, this is SectionIDCode.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#code-section%E2%91%A0
	CodeSection []Code

	// Note: In the Binary Format, this is SectionIDData.
	DataSection []DataSegment

	// NameSection is set when the SectionIDCustom "name" was successfully decoded from the binary format.
	//
	// Note: This is the only SectionIDCustom defined in the WebAssembly 1.0 (20191205) Binary Format.
	// Others are skipped as they are not used in wazero.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#name-section%E2%91%A0
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#custom-section%E2%91%A0
	NameSection *NameSection

	// CustomSections are set when the SectionIDCustom other than "name" were successfully decoded from the binary format.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#custom-section%E2%91%A0
	CustomSections []*CustomSection

	// DataCountSection is the optional section and holds the number of data segments in the data section.
	//
	// Note: This may exist in WebAssembly 2.0 or WebAssembly 1.0 with CoreFeatureBulkMemoryOperations.
	// See https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/binary/modules.html#data-count-section
	// See https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/appendix/changes.html#bulk-memory-and-table-instructions
	DataCountSection *uint32

	// ID is the sha256 value of the source wasm plus the configurations which affect the runtime representation of
	// Wasm binary. This is only used for caching.
	ID ModuleID

	// IsHostModule true if this is the host module, false otherwise.
	IsHostModule bool

	// functionDefinitionSectionInitOnce guards FunctionDefinitionSection so that it is initialized exactly once.
	functionDefinitionSectionInitOnce sync.Once

	// FunctionDefinitionSection is a wazero-specific section.
	FunctionDefinitionSection []FunctionDefinition

	// MemoryDefinitionSection is a wazero-specific section.
	MemoryDefinitionSection []MemoryDefinition

	// DWARFLines is used to emit DWARF based stack trace. This is created from the multiple custom sections
	// as described in https://yurydelendik.github.io/webassembly-dwarf/, though it is not specified in the Wasm
	// specification: https://github.com/WebAssembly/debugging/issues/1
	DWARFLines *wasmdebug.DWARFLines
}

// ModuleID represents sha256 hash value uniquely assigned to Module.
type ModuleID = [sha256.Size]byte

// The wazero specific limitation described at RATIONALE.md.
// TL;DR; We multiply by 8 (to get offsets in bytes) and the multiplication result must be less than 32bit max
const (
	MaximumGlobals       = uint32(1 << 27)
	MaximumFunctionIndex = uint32(1 << 27)
	MaximumTableIndex    = uint32(1 << 27)
)

// AssignModuleID calculates a sha256 checksum on `wasm` and other args, and set Module.ID to the result.
// See the doc on Module.ID on what it's used for.
func (m *Module) AssignModuleID(wasm []byte, listeners []experimental.FunctionListener, withEnsureTermination bool) {
	h := sha256.New()
	h.Write(wasm)
	// Use the pre-allocated space backed by m.ID below.

	// Write the existence of listeners to the checksum per function.
	for i, l := range listeners {
		binary.LittleEndian.PutUint32(m.ID[:], uint32(i))
		m.ID[4] = boolToByte(l != nil)
		h.Write(m.ID[:5])
	}
	// Write the flag of ensureTermination to the checksum.
	m.ID[0] = boolToByte(withEnsureTermination)
	h.Write(m.ID[:1])
	// Get checksum by passing the slice underlying m.ID.
	h.Sum(m.ID[:0])
}

func boolToByte(b bool) (ret byte) {
	if b {
		ret = 1
	}
	return
}

// typeOfFunction returns the wasm.FunctionType for the given function space index or nil.
func (m *Module) typeOfFunction(funcIdx Index) *FunctionType {
	typeIdx, ok := m.typeIndexOfFunction(funcIdx)
	if !ok {
		return nil
	}
	return &m.TypeSection[typeIdx]
}

// typeIndexOfFunction returns the type section index for the given function
// space index, or false if the index is out of range.
func (m *Module) typeIndexOfFunction(funcIdx Index) (Index, bool) {
	typeSectionLength, importedFunctionCount := uint32(len(m.TypeSection)), m.ImportFunctionCount
	if funcIdx < importedFunctionCount {
		// Imports are not exclusively functions. This is the current function index in the loop.
		cur := Index(0)
		for i := range m.ImportSection {
			imp := &m.ImportSection[i]
			if imp.Type != ExternTypeFunc {
				continue
			}
			if funcIdx == cur {
				if imp.DescFunc >= typeSectionLength {
					return 0, false
				}
				return imp.DescFunc, true
			}
			cur++
		}
	}

	funcSectionIdx := funcIdx - m.ImportFunctionCount
	if funcSectionIdx >= uint32(len(m.FunctionSection)) {
		return 0, false
	}
	typeIdx := m.FunctionSection[funcSectionIdx]
	if typeIdx >= typeSectionLength {
		return 0, false
	}
	return typeIdx, true
}

func (m *Module) Validate(enabledFeatures api.CoreFeatures) error {
	for i := range m.TypeSection {
		tp := &m.TypeSection[i]
		tp.CacheNumInUint64()
	}

	if err := m.validateConcreteRefTypes(); err != nil {
		return err
	}

	if err := m.validateStartSection(); err != nil {
		return err
	}

	functions, globals, memory, tables, tags, err := m.AllDeclarations()
	if err != nil {
		return err
	}

	if err = m.validateTableInitExprs(globals, uint32(len(functions))); err != nil {
		return err
	}

	if err = m.validateImports(enabledFeatures); err != nil {
		return err
	}

	if err = m.validateGlobals(globals, uint32(len(functions)), MaximumGlobals); err != nil {
		return err
	}

	if err = m.validateMemory(memory, globals, enabledFeatures); err != nil {
		return err
	}

	if err = m.validateExports(enabledFeatures, functions, globals, memory, tables, tags); err != nil {
		return err
	}

	if m.CodeSection != nil {
		if err = m.validateFunctions(enabledFeatures, functions, globals, memory, tables, tags, MaximumFunctionIndex); err != nil {
			return err
		}
	} // No need to validate host functions as NewHostModule validates

	if err = m.validateTable(enabledFeatures, tables, MaximumTableIndex); err != nil {
		return err
	}

	if err = m.validateDataCountSection(); err != nil {
		return err
	}

	if err = m.validateTagSection(); err != nil {
		return err
	}
	return nil
}

func (m *Module) validateConcreteRefTypes() error {
	numTypes := uint32(len(m.TypeSection))
	for i, g := range m.GlobalSection {
		if vt := g.Type.ValType; vt.IsConcreteRef() && vt.TypeIndex() >= numTypes {
			return fmt.Errorf("unknown type %d in global[%d]", vt.TypeIndex(), i)
		}
	}
	for i, t := range m.TableSection {
		if vt := t.Type; vt.IsConcreteRef() && vt.TypeIndex() >= numTypes {
			return fmt.Errorf("unknown type %d in table[%d]", vt.TypeIndex(), i)
		}
	}
	for i, c := range m.CodeSection {
		for j, lt := range c.LocalTypes {
			if lt.IsConcreteRef() && lt.TypeIndex() >= numTypes {
				return fmt.Errorf("unknown type %d in func[%d].local[%d]", lt.TypeIndex(), i, j)
			}
		}
	}
	for i, e := range m.ElementSection {
		if vt := e.Type; vt.IsConcreteRef() && vt.TypeIndex() >= numTypes {
			return fmt.Errorf("unknown type %d in element[%d]", vt.TypeIndex(), i)
		}
	}
	return nil
}

func (m *Module) validateTableInitExprs(globals []GlobalType, numFuncs uint32) error {
	importedGlobals := globals[:m.ImportGlobalCount]
	for i, t := range m.TableSection {
		if !t.Type.IsNullable() && t.InitExpr == nil {
			return fmt.Errorf("type mismatch: non-nullable table[%d] requires an init expression", i)
		}
		if t.InitExpr != nil {
			if err := m.validateConstExpression(importedGlobals, numFuncs, t.InitExpr, t.Type); err != nil {
				return fmt.Errorf("table[%d] init: %w", i, err)
			}
		}
	}
	return nil
}

func (m *Module) validateTagSection() error {
	for i, tag := range m.TagSection {
		if tag.Type >= uint32(len(m.TypeSection)) {
			return fmt.Errorf("tag[%d] type index out of range", i)
		}
		ft := &m.TypeSection[tag.Type]
		if len(ft.Results) > 0 {
			return fmt.Errorf("tag[%d] type must have empty results, got %v", i, ft.Results)
		}
	}
	return nil
}

func (m *Module) validateStartSection() error {
	// Check the start function is valid.
	// TODO: this should be verified during decode so that errors have the correct source positions
	if m.StartSection != nil {
		startIndex := *m.StartSection
		ft := m.typeOfFunction(startIndex)
		if ft == nil { // TODO: move this check to decoder so that a module can never be decoded invalidly
			return fmt.Errorf("invalid start function: func[%d] has an invalid type", startIndex)
		}
		if len(ft.Params) > 0 || len(ft.Results) > 0 {
			return fmt.Errorf("invalid start function: func[%d] must have an empty (nullary) signature: %s", startIndex, ft)
		}
	}
	return nil
}

func (m *Module) validateGlobals(globals []GlobalType, numFuncts, maxGlobals uint32) error {
	if uint32(len(globals)) > maxGlobals {
		return fmt.Errorf("too many globals in a module")
	}

	// Global initialization constant expression can only reference the imported globals.
	// See the note on https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#constant-expressions%E2%91%A0
	importedGlobals := globals[:m.ImportGlobalCount]
	for i := range m.GlobalSection {
		g := &m.GlobalSection[i]
		if err := m.validateConstExpression(importedGlobals, numFuncts, &g.Init, g.Type.ValType); err != nil {
			return err
		}
	}
	return nil
}

func (m *Module) validateFunctions(enabledFeatures api.CoreFeatures, functions []Index, globals []GlobalType, memory *Memory, tables []Table, tags []Index, maximumFunctionIndex uint32) error {
	if uint32(len(functions)) > maximumFunctionIndex {
		return fmt.Errorf("too many functions (%d) in a module", len(functions))
	}

	functionCount := m.SectionElementCount(SectionIDFunction)
	codeCount := m.SectionElementCount(SectionIDCode)
	if functionCount == 0 && codeCount == 0 {
		return nil
	}

	typeCount := m.SectionElementCount(SectionIDType)
	if codeCount != functionCount {
		return fmt.Errorf("code count (%d) != function count (%d)", codeCount, functionCount)
	}

	declaredFuncIndexes, err := m.declaredFunctionIndexes(enabledFeatures)
	if err != nil {
		return err
	}

	// Create bytes.Reader once as it causes allocation, and
	// we frequently need it (e.g. on every If instruction).
	br := bytes.NewReader(nil)
	// Also, we reuse the stacks across multiple function validations to reduce allocations.
	vs := &stacks{}
	for idx, typeIndex := range m.FunctionSection {
		if typeIndex >= typeCount {
			return fmt.Errorf("invalid %s: type section index %d out of range", m.funcDesc(SectionIDFunction, Index(idx)), typeIndex)
		}
		c := &m.CodeSection[idx]
		if c.GoFunc != nil {
			continue
		}
		if err = m.validateFunction(vs, enabledFeatures, Index(idx), functions, globals, memory, tables, tags, declaredFuncIndexes, br); err != nil {
			return fmt.Errorf("invalid %s: %w", m.funcDesc(SectionIDFunction, Index(idx)), err)
		}
	}
	return nil
}

// declaredFunctionIndexes returns a set of function indexes that can be used as an immediate for OpcodeRefFunc instruction.
//
// The criteria for which function indexes can be available for that instruction is vague in the spec:
//
//   - "References: the list of function indices that occur in the module outside functions and can hence be used to form references inside them."
//   - https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/valid/conventions.html#contexts
//   - "Ref is the set funcidx(module with functions=ε, start=ε) , i.e., the set of function indices occurring in the module, except in its functions or start function."
//   - https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/valid/modules.html#valid-module
//
// To clarify, we reverse-engineer logic required to pass the WebAssembly Core specification 2.0 test suite:
// https://github.com/WebAssembly/spec/blob/d39195773112a22b245ffbe864bab6d1182ccb06/test/core/ref_func.wast#L78-L115
//
// To summarize, the function indexes OpcodeRefFunc can refer include:
//   - existing in an element section regardless of its mode (active, passive, declarative).
//   - defined as globals whose value type is ValueRefFunc.
//   - used as an exported function.
//
// See https://github.com/WebAssembly/reference-types/issues/31
// See https://github.com/WebAssembly/reference-types/issues/76
func (m *Module) declaredFunctionIndexes(enabledFeatures api.CoreFeatures) (ret map[Index]struct{}, err error) {
	ret = map[uint32]struct{}{}

	for i := range m.ExportSection {
		exp := &m.ExportSection[i]
		if exp.Type == ExternTypeFunc {
			ret[exp.Index] = struct{}{}
		}
	}

	for i := range m.GlobalSection {
		g := &m.GlobalSection[i]

		_, _, initErr := evaluateConstExpr(
			&g.Init,
			func(globalIndex Index) (ValueType, uint64, uint64, error) {
				vt, err := m.resolveConstExprGlobalType(enabledFeatures, SectionIDGlobal, Index(i), globalIndex)
				return vt, 0, 0, err
			},
			func(funcIndex Index) (Reference, error) {
				ret[funcIndex] = struct{}{}
				return 0, nil
			},
		)

		if initErr != nil {
			err = fmt.Errorf("%s[%d] failed to initialize: %w", SectionIDName(SectionIDGlobal), i, initErr)
			return
		}
	}

	for i := range m.ElementSection {
		elem := &m.ElementSection[i]
		for _, initExpr := range elem.Init {
			_, _, _ = evaluateConstExpr(
				&initExpr,
				func(globalIndex Index) (ValueType, uint64, uint64, error) {
					vt, err := m.resolveConstExprGlobalType(enabledFeatures, SectionIDElement, Index(i), globalIndex)
					return vt, 0, 0, err
				},
				func(funcIndex Index) (Reference, error) {
					ret[funcIndex] = struct{}{}
					return 0, nil
				},
			)
		}
	}
	return
}

func (m *Module) funcDesc(sectionID SectionID, sectionIndex Index) string {
	// Try to improve the error message by collecting any exports:
	var exportNames []string
	funcIdx := sectionIndex + m.ImportFunctionCount
	for i := range m.ExportSection {
		exp := &m.ExportSection[i]
		if exp.Index == funcIdx && exp.Type == ExternTypeFunc {
			exportNames = append(exportNames, fmt.Sprintf("%q", exp.Name))
		}
	}
	sectionIDName := SectionIDName(sectionID)
	if exportNames == nil {
		return fmt.Sprintf("%s[%d]", sectionIDName, sectionIndex)
	}
	sort.Strings(exportNames) // go map keys do not iterate consistently
	return fmt.Sprintf("%s[%d] export[%s]", sectionIDName, sectionIndex, strings.Join(exportNames, ","))
}

func (m *Module) validateMemory(memory *Memory, globals []GlobalType, _ api.CoreFeatures) error {
	var activeElementCount int
	for i := range m.DataSection {
		d := &m.DataSection[i]
		if !d.IsPassive() {
			activeElementCount++
		}
	}
	if activeElementCount > 0 && memory == nil {
		return fmt.Errorf("unknown memory")
	}

	// Constant expression can only reference imported globals.
	// https://github.com/WebAssembly/spec/blob/5900d839f38641989a9d8df2df4aee0513365d39/test/core/data.wast#L84-L91
	importedGlobals := globals[:m.ImportGlobalCount]
	for i := range m.DataSection {
		d := &m.DataSection[i]
		if !d.IsPassive() {
			if err := m.validateConstExpression(importedGlobals, 0, &d.OffsetExpression, ValueTypeI32); err != nil {
				return fmt.Errorf("calculate offset: %w", err)
			}
		}
	}
	return nil
}

func (m *Module) validateImports(enabledFeatures api.CoreFeatures) error {
	for i := range m.ImportSection {
		imp := &m.ImportSection[i]
		if imp.Module == "" {
			return fmt.Errorf("import[%d] has an empty module name", i)
		}
		switch imp.Type {
		case ExternTypeFunc:
			if int(imp.DescFunc) >= len(m.TypeSection) {
				return fmt.Errorf("invalid import[%q.%q] function: type index out of range", imp.Module, imp.Name)
			}
		case ExternTypeGlobal:
			if !imp.DescGlobal.Mutable {
				continue
			}
			if err := enabledFeatures.RequireEnabled(api.CoreFeatureMutableGlobal); err != nil {
				return fmt.Errorf("invalid import[%q.%q] global: %w", imp.Module, imp.Name, err)
			}
		case ExternTypeTag:
			if int(imp.DescTag) >= len(m.TypeSection) {
				return fmt.Errorf("invalid import[%q.%q] tag: type index out of range", imp.Module, imp.Name)
			}
			if len(m.TypeSection[imp.DescTag].Results) > 0 {
				return fmt.Errorf("invalid import[%q.%q] tag: tag types must have no results", imp.Module, imp.Name)
			}
		}
	}
	return nil
}

func (m *Module) validateExports(enabledFeatures api.CoreFeatures, functions []Index, globals []GlobalType, memory *Memory, tables []Table, tags []Index) error {
	for i := range m.ExportSection {
		exp := &m.ExportSection[i]
		index := exp.Index
		switch exp.Type {
		case ExternTypeFunc:
			if index >= uint32(len(functions)) {
				return fmt.Errorf("unknown function for export[%q]", exp.Name)
			}
		case ExternTypeGlobal:
			if index >= uint32(len(globals)) {
				return fmt.Errorf("unknown global for export[%q]", exp.Name)
			}
			if !globals[index].Mutable {
				continue
			}
			if err := enabledFeatures.RequireEnabled(api.CoreFeatureMutableGlobal); err != nil {
				return fmt.Errorf("invalid export[%q] global[%d]: %w", exp.Name, index, err)
			}
		case ExternTypeMemory:
			if index > 0 || memory == nil {
				return fmt.Errorf("memory for export[%q] out of range", exp.Name)
			}
		case ExternTypeTable:
			if index >= uint32(len(tables)) {
				return fmt.Errorf("table for export[%q] out of range", exp.Name)
			}
		case ExternTypeTag:
			if index >= uint32(len(tags)) {
				return fmt.Errorf("tag for export[%q] out of range", exp.Name)
			}
		}
	}
	return nil
}

func (m *Module) validateConstExpression(globals []GlobalType, numFuncs uint32, expr *ConstantExpression, expectedType ValueType) (err error) {
	var lastRefFuncIdx Index
	_, typ, err := evaluateConstExpr(
		expr,
		func(globalIndex Index) (ValueType, uint64, uint64, error) {
			if uint32(len(globals)) <= globalIndex {
				return 0, 0, 0, fmt.Errorf("global index out of range")
			}
			return globals[globalIndex].ValType, 0, 0, nil
		},
		func(funcIndex Index) (Reference, error) {
			if funcIndex >= numFuncs {
				return 0, fmt.Errorf("ref.func index out of range [%d] with length %d", funcIndex, numFuncs-1)
			}
			lastRefFuncIdx = funcIndex
			return 0, nil
		},
	)
	if err != nil {
		return err
	}
	if typ == ValueTypeFuncref {
		if typeIndex, ok := m.typeIndexOfFunction(lastRefFuncIdx); ok {
			typ = ValueTypeConcreteRef(typeIndex, false)
		}
	}
	if !isRefSubtypeOf(typ, expectedType) {
		return fmt.Errorf("const expression type mismatch expected %s but got %s", ValueTypeName(expectedType), ValueTypeName(typ))
	}
	return nil
}

func (m *Module) validateDataCountSection() (err error) {
	if m.DataCountSection != nil && int(*m.DataCountSection) != len(m.DataSection) {
		err = fmt.Errorf("data count section (%d) doesn't match the length of data section (%d)",
			*m.DataCountSection, len(m.DataSection))
	}
	return
}

func (m *ModuleInstance) buildTags(module *Module) {
	for i := range module.TagSection {
		tag := &module.TagSection[i]
		t := &TagInstance{
			Type: &module.TypeSection[tag.Type],
		}
		m.Tags[i+int(module.ImportTagCount)] = t
	}
}

func (m *ModuleInstance) buildGlobals(module *Module, funcRefResolver func(funcIndex Index) Reference) {
	importedGlobals := m.Globals[:module.ImportGlobalCount]

	me := m.Engine
	engineOwnGlobal := me.OwnsGlobals()
	for i := Index(0); i < Index(len(module.GlobalSection)); i++ {
		gs := &module.GlobalSection[i]
		g := &GlobalInstance{}
		if engineOwnGlobal {
			g.Me = me
			g.Index = i + module.ImportGlobalCount
		}
		m.Globals[i+module.ImportGlobalCount] = g
		g.Type = gs.Type
		g.initialize(importedGlobals, &gs.Init, funcRefResolver)
	}
}

func (m *Module) resolveConstExprGlobalType(enabledFeatures api.CoreFeatures, sectionID SectionID, sectionIdx Index, idx Index) (ValueType, error) {
	if idx < m.ImportGlobalCount {
		// Imports are not exclusively globals. This is the current global index in the loop.
		cur := uint32(0)
		for i := range m.ImportSection {
			imp := &m.ImportSection[i]
			if imp.Type != ExternTypeGlobal {
				continue
			}
			if idx == cur {
				return imp.DescGlobal.ValType, nil
			}
			cur++
		}

		// should not happen as idx < ImportGlobalCount
		return 0, fmt.Errorf("index %d not found in imported globals", idx)
	}

	// NOTE: in the <= 2.0 spec, global.get in a constant expression can only refer to imported globals.
	// In version 3.0, this restriction is removed, and all globals prior to the current one are allowed.
	// To avoid implementing too many flags, this relaxation is gated behind the CoreFeaturesExtendedConst flag,
	// which includes other related extensions in constant expressions.
	if !enabledFeatures.IsEnabled(experimental.CoreFeaturesExtendedConst) {
		return 0, fmt.Errorf("%s[%d] (global.get %d): out of range of imported globals", SectionIDName(sectionID), sectionIdx, idx)
	}

	idx -= uint32(m.ImportGlobalCount)

	// Check that the given global has been initialized.
	if sectionIdx == Index(SectionIDGlobal) && idx >= sectionIdx {
		return 0, fmt.Errorf("%s[%d] global %d out of range of initialized globals", SectionIDName(sectionID), sectionIdx, idx)
	}

	// Bounds check:
	if idx >= uint32(len(m.GlobalSection)) {
		return 0, fmt.Errorf("%s[%d] (global.get %d): out of range of initialized globals", SectionIDName(sectionID), sectionIdx, idx)
	}

	return m.GlobalSection[idx].Type.ValType, nil
}

func paramNames(localNames IndirectNameMap, funcIdx uint32, paramLen int) []string {
	for i := range localNames {
		nm := &localNames[i]
		// Only build parameter names if we have one for each.
		if nm.Index != funcIdx || len(nm.NameMap) < paramLen {
			continue
		}

		ret := make([]string, paramLen)
		for j := range nm.NameMap {
			p := &nm.NameMap[j]
			if int(p.Index) < paramLen {
				ret[p.Index] = p.Name
			}
		}
		return ret
	}
	return nil
}

func (m *ModuleInstance) buildMemory(module *Module, allocator experimental.MemoryAllocator) {
	memSec := module.MemorySection
	if memSec != nil {
		m.MemoryInstance = NewMemoryInstance(memSec, allocator, m.Engine)
		m.MemoryInstance.definition = &module.MemoryDefinitionSection[0]
	}
}

// Index is the offset in an index, not necessarily an absolute position in a Module section. This is because
// indexs are often preceded by a corresponding type in the Module.ImportSection.
//
// For example, the function index starts with any ExternTypeFunc in the Module.ImportSection followed by
// the Module.FunctionSection
//
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-index
type Index = uint32

// FunctionType is a possibly empty function signature.
//
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#function-types%E2%91%A0
type FunctionType struct {
	// Params are the possibly empty sequence of value types accepted by a function with this signature.
	Params []ValueType

	// Results are the possibly empty sequence of value types returned by a function with this signature.
	//
	// Note: In WebAssembly 1.0 (20191205), there can be at most one result.
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#result-types%E2%91%A0
	Results []ValueType

	// string is cached as it is used both for String and key
	string string

	// ParamNumInUint64 is the number of uint64 values requires to represent the Wasm param type.
	ParamNumInUint64 int

	// ResultsNumInUint64 is the number of uint64 values requires to represent the Wasm result type.
	ResultNumInUint64 int

	// RecGroupSize is the size of the rec group this type belongs to.
	// Standalone types (not in an explicit rec group) have RecGroupSize 1.
	RecGroupSize int

	// RecGroupPosition is the 0-based position of this type within its rec group.
	RecGroupPosition int
}

func (f *FunctionType) CacheNumInUint64() {
	if f.ParamNumInUint64 == 0 {
		for _, tp := range f.Params {
			f.ParamNumInUint64++
			if tp == ValueTypeV128 {
				f.ParamNumInUint64++
			}
		}
	}

	if f.ResultNumInUint64 == 0 {
		for _, tp := range f.Results {
			f.ResultNumInUint64++
			if tp == ValueTypeV128 {
				f.ResultNumInUint64++
			}
		}
	}
}

// EqualsSignature returns true if the function type has the same parameters and results.
func (f *FunctionType) EqualsSignature(params []ValueType, results []ValueType) bool {
	return slices.Equal(f.Params, params) && slices.Equal(f.Results, results)
}

// EqualsType returns true if the function types are structurally equal AND
// belong to the same rec group position/size (GC proposal type identity).
func (f *FunctionType) EqualsType(other *FunctionType) bool {
	if !f.EqualsSignature(other.Params, other.Results) {
		return false
	}
	return f.RecGroupSize == other.RecGroupSize && f.RecGroupPosition == other.RecGroupPosition
}

// key gets or generates the key for Store.typeIDs. e.g. "i32_v" for one i32 parameter and no (void) result.
func (f *FunctionType) key() string {
	if f.string != "" {
		return f.string
	}
	var ret string
	for _, b := range f.Params {
		ret += ValueTypeName(b)
	}
	if len(f.Params) == 0 {
		ret += "v_"
	} else {
		ret += "_"
	}
	for _, b := range f.Results {
		ret += ValueTypeName(b)
	}
	if len(f.Results) == 0 {
		ret += "v"
	}
	if f.RecGroupSize > 1 {
		ret += fmt.Sprintf("|rec%d/%d", f.RecGroupPosition, f.RecGroupSize)
	}
	f.string = ret
	return ret
}

// String implements fmt.Stringer.
func (f *FunctionType) String() string {
	return f.key()
}

// Import is the binary representation of an import indicated by Type
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-import
type Import struct {
	Type ExternType
	// Module is the possibly empty primary namespace of this import
	Module string
	// Module is the possibly empty secondary namespace of this import
	Name string
	// DescFunc is the index in Module.TypeSection when Type equals ExternTypeFunc
	DescFunc Index
	// DescTable is the inlined Table when Type equals ExternTypeTable
	DescTable Table
	// DescMem is the inlined Memory when Type equals ExternTypeMemory
	DescMem *Memory
	// DescGlobal is the inlined GlobalType when Type equals ExternTypeGlobal
	DescGlobal GlobalType
	// DescTag is the type index when Type equals ExternTypeTag
	DescTag Index
	// IndexPerType has the index of this import per ExternType.
	IndexPerType Index
}

// Memory describes the limits of pages (64KB) in a memory.
type Memory struct {
	Min, Cap, Max uint32
	// IsMaxEncoded true if the Max is encoded in the original binary.
	IsMaxEncoded bool
	// IsShared true if the memory is shared for access from multiple agents.
	IsShared bool
}

// Validate ensures values assigned to Min, Cap and Max are within valid thresholds.
func (m *Memory) Validate(memoryLimitPages uint32) error {
	min, capacity, max := m.Min, m.Cap, m.Max

	if max > memoryLimitPages {
		return fmt.Errorf("max %d pages (%s) over limit of %d pages (%s)",
			max, PagesToUnitOfBytes(max), memoryLimitPages, PagesToUnitOfBytes(memoryLimitPages))
	} else if min > memoryLimitPages {
		return fmt.Errorf("min %d pages (%s) over limit of %d pages (%s)",
			min, PagesToUnitOfBytes(min), memoryLimitPages, PagesToUnitOfBytes(memoryLimitPages))
	} else if min > max {
		return fmt.Errorf("min %d pages (%s) > max %d pages (%s)",
			min, PagesToUnitOfBytes(min), max, PagesToUnitOfBytes(max))
	} else if capacity < min {
		return fmt.Errorf("capacity %d pages (%s) less than minimum %d pages (%s)",
			capacity, PagesToUnitOfBytes(capacity), min, PagesToUnitOfBytes(min))
	} else if capacity > memoryLimitPages {
		return fmt.Errorf("capacity %d pages (%s) over limit of %d pages (%s)",
			capacity, PagesToUnitOfBytes(capacity), memoryLimitPages, PagesToUnitOfBytes(memoryLimitPages))
	}
	return nil
}

// Tag represents an exception tag defined in the tag section.
// The Type field is an index into the TypeSection; the referenced function type
// must have empty results (tags carry parameters but produce no results).
type Tag struct {
	Type Index
}

type GlobalType struct {
	ValType ValueType
	Mutable bool
}

type Global struct {
	Type GlobalType
	Init ConstantExpression
}

// Export is the binary representation of an export indicated by Type
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-export
type Export struct {
	Type ExternType

	// Name is what the host refers to this definition as.
	Name string

	// Index is the index of the definition to export, the index is by Type
	// e.g. If ExternTypeFunc, this is a position in the function index.
	Index Index
}

// Code is an entry in the Module.CodeSection containing the locals and body of the function.
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-code
type Code struct {
	// LocalTypes are any function-scoped variables in insertion order.
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-local
	LocalTypes []ValueType

	// Body is a sequence of expressions ending in OpcodeEnd
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-expr
	Body []byte

	// GoFunc is non-nil when IsHostFunction and defined in go, either
	// api.GoFunction or api.GoModuleFunction. When present, LocalTypes and Body must
	// be nil.
	//
	// Note: This has no serialization format, so is not encodable.
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#host-functions%E2%91%A2
	GoFunc interface{}

	// BodyOffsetInCodeSection is the offset of the beginning of the body in the code section.
	// This is used for DWARF based stack trace where a program counter represents an offset in code section.
	BodyOffsetInCodeSection uint64
}

type DataSegment struct {
	OffsetExpression ConstantExpression
	Init             []byte
	Passive          bool
}

// IsPassive returns true if this data segment is "passive" in the sense that memory offset and
// index is determined at runtime and used by OpcodeMemoryInitName instruction in the bulk memory
// operations proposal.
//
// See https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/appendix/changes.html#bulk-memory-and-table-instructions
func (d *DataSegment) IsPassive() bool {
	return d.Passive
}

// NameSection represent the known custom name subsections defined in the WebAssembly Binary Format
//
// Note: This can be nil if no names were decoded for any reason including configuration.
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#name-section%E2%91%A0
type NameSection struct {
	// ModuleName is the symbolic identifier for a module. e.g. math
	//
	// Note: This can be empty for any reason including configuration.
	ModuleName string

	// FunctionNames is an association of a function index to its symbolic identifier. e.g. add
	//
	// * the key (idx) is in the function index, where module defined functions are preceded by imported ones.
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#functions%E2%91%A7
	//
	// For example, assuming the below text format is the second import, you would expect FunctionNames[1] = "mul"
	//	(import "Math" "Mul" (func $mul (param $x f32) (param $y f32) (result f32)))
	//
	// Note: FunctionNames are only used for debugging. At runtime, functions are called based on raw numeric index.
	// Note: This can be nil for any reason including configuration.
	FunctionNames NameMap

	// LocalNames contains symbolic names for function parameters or locals that have one.
	//
	// Note: In the Text Format, function local names can inherit parameter
	// names from their type. Here are some examples:
	//  * (module (import (func (param $x i32) (param i32))) (func (type 0))) = [{0, {x,0}}]
	//  * (module (import (func (param i32) (param $y i32))) (func (type 0) (local $z i32))) = [0, [{y,1},{z,2}]]
	//  * (module (func (param $x i32) (local $y i32) (local $z i32))) = [{x,0},{y,1},{z,2}]
	//
	// Note: LocalNames are only used for debugging. At runtime, locals are called based on raw numeric index.
	// Note: This can be nil for any reason including configuration.
	LocalNames IndirectNameMap

	// ResultNames is a wazero-specific mechanism to store result names.
	ResultNames IndirectNameMap
}

// CustomSection contains the name and raw data of a custom section.
type CustomSection struct {
	Name string
	Data []byte
}

// NameMap associates an index with any associated names.
//
// Note: Often the index bridges multiple sections. For example, the function index starts with any
// ExternTypeFunc in the Module.ImportSection followed by the Module.FunctionSection
//
// Note: NameMap is unique by NameAssoc.Index, but NameAssoc.Name needn't be unique.
// Note: When encoding in the Binary format, this must be ordered by NameAssoc.Index
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-namemap
type NameMap []NameAssoc

type NameAssoc struct {
	Index Index
	Name  string
}

// IndirectNameMap associates an index with an association of names.
//
// Note: IndirectNameMap is unique by NameMapAssoc.Index, but NameMapAssoc.NameMap needn't be unique.
// Note: When encoding in the Binary format, this must be ordered by NameMapAssoc.Index
// https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-indirectnamemap
type IndirectNameMap []NameMapAssoc

type NameMapAssoc struct {
	Index   Index
	NameMap NameMap
}

// AllDeclarations returns all declarations for functions, globals, memories, tables and tags in a module including imported ones.
func (m *Module) AllDeclarations() (functions []Index, globals []GlobalType, memory *Memory, tables []Table, tags []Index, err error) {
	for i := range m.ImportSection {
		imp := &m.ImportSection[i]
		switch imp.Type {
		case ExternTypeFunc:
			functions = append(functions, imp.DescFunc)
		case ExternTypeGlobal:
			globals = append(globals, imp.DescGlobal)
		case ExternTypeMemory:
			memory = imp.DescMem
		case ExternTypeTable:
			tables = append(tables, imp.DescTable)
		case ExternTypeTag:
			tags = append(tags, imp.DescTag)
		}
	}

	functions = append(functions, m.FunctionSection...)
	for i := range m.GlobalSection {
		g := &m.GlobalSection[i]
		globals = append(globals, g.Type)
	}
	for i := range m.TagSection {
		t := &m.TagSection[i]
		tags = append(tags, t.Type)
	}
	if m.MemorySection != nil {
		if memory != nil { // shouldn't be possible due to Validate
			err = errors.New("at most one table allowed in module")
			return
		}
		memory = m.MemorySection
	}
	if m.TableSection != nil {
		tables = append(tables, m.TableSection...)
	}
	return
}

// SectionID identifies the sections of a Module in the WebAssembly 1.0 (20191205) Binary Format.
//
// Note: these are defined in the wasm package, instead of the binary package, as a key per section is needed regardless
// of format, and deferring to the binary type avoids confusion.
//
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#sections%E2%91%A0
type SectionID = byte

const (
	// SectionIDCustom includes the standard defined NameSection and possibly others not defined in the standard.
	SectionIDCustom SectionID = iota // don't add anything not in https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#sections%E2%91%A0
	SectionIDType
	SectionIDImport
	SectionIDFunction
	SectionIDTable
	SectionIDMemory
	SectionIDGlobal
	SectionIDExport
	SectionIDStart
	SectionIDElement
	SectionIDCode
	SectionIDData

	// SectionIDDataCount may exist in WebAssembly 2.0 or WebAssembly 1.0 with CoreFeatureBulkMemoryOperations enabled.
	//
	// See https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/binary/modules.html#data-count-section
	// See https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/appendix/changes.html#bulk-memory-and-table-instructions
	SectionIDDataCount

	// SectionIDTag is for exception handling tags.
	//
	// See https://github.com/WebAssembly/exception-handling/blob/main/proposals/exception-handling/Exceptions.md
	SectionIDTag SectionID = 13
)

// SectionIDName returns the canonical name of a module section.
// https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#sections%E2%91%A0
func SectionIDName(sectionID SectionID) string {
	switch sectionID {
	case SectionIDCustom:
		return "custom"
	case SectionIDType:
		return "type"
	case SectionIDImport:
		return "import"
	case SectionIDFunction:
		return "function"
	case SectionIDTable:
		return "table"
	case SectionIDMemory:
		return "memory"
	case SectionIDGlobal:
		return "global"
	case SectionIDExport:
		return "export"
	case SectionIDStart:
		return "start"
	case SectionIDElement:
		return "element"
	case SectionIDCode:
		return "code"
	case SectionIDData:
		return "data"
	case SectionIDDataCount:
		return "data_count"
	case SectionIDTag:
		return "tag"
	}
	return "unknown"
}

// ValueType represents a WebAssembly value type as a uint64.
//
// Layout:
//
//	bits  0-7:  kind byte (backward-compatible with api.ValueType)
//	bits  8-15: flags (nullability, concrete ref)
//	bits 32-63: type index (for concrete refs like (ref $3))
type ValueType uint64

const (
	flagNonNullable ValueType = 1 << 8
	flagConcreteRef ValueType = 1 << 9
)

const (
	ValueTypeI32       ValueType = 0x7f
	ValueTypeI64       ValueType = 0x7e
	ValueTypeF32       ValueType = 0x7d
	ValueTypeF64       ValueType = 0x7c
	ValueTypeV128      ValueType = 0x7b
	ValueTypeFuncref   ValueType = 0x70
	ValueTypeExternref ValueType = 0x6f
	ValueTypeExnref    ValueType = 0x69
)

// Kind returns the base type byte (bits 0-7).
func (v ValueType) Kind() byte { return byte(v) }

// IsRef returns true if this is a reference type (including non-nullable variants).
func (v ValueType) IsRef() bool {
	k := v.Kind()
	return k == ValueTypeFuncref.Kind() || k == ValueTypeExternref.Kind() || k == ValueTypeExnref.Kind() ||
		v&flagConcreteRef != 0
}

// IsNullable returns true if this reference type is nullable. Must only be called on ref types.
func (v ValueType) IsNullable() bool { return v.IsRef() && v&flagNonNullable == 0 }

// IsConcreteRef returns true if this is a concrete reference type with a type index.
func (v ValueType) IsConcreteRef() bool { return v&flagConcreteRef != 0 }

// TypeIndex returns the concrete type index (bits 32-63).
func (v ValueType) TypeIndex() uint32 { return uint32(v >> 32) }

// AsNonNullable returns a copy with the non-nullable flag set.
func (v ValueType) AsNonNullable() ValueType { return v | flagNonNullable }

// AsNullable returns a copy with the non-nullable flag cleared.
func (v ValueType) AsNullable() ValueType { return v &^ flagNonNullable }

// ValueTypeConcreteRef creates a concrete reference type with the given type index and nullability.
func ValueTypeConcreteRef(typeIndex uint32, nullable bool) ValueType {
	v := ValueTypeFuncref | flagConcreteRef | ValueType(typeIndex)<<32
	if !nullable {
		v |= flagNonNullable
	}
	return v
}

const (
	// RefPrefixNullable is the binary encoding prefix for nullable reference types (ref null <heaptype>).
	RefPrefixNullable byte = 0x63
	// RefPrefixNonNullable is the binary encoding prefix for non-nullable reference types (ref <heaptype>).
	RefPrefixNonNullable byte = 0x64
)

const (
	// HeapTypeFunc is the abstract heap type for function references.
	HeapTypeFunc int64 = -16
	// HeapTypeExtern is the abstract heap type for external references.
	HeapTypeExtern int64 = -17
	// HeapTypeExn is the abstract heap type for exception references.
	HeapTypeExn int64 = -23
)

// ValueTypeName returns the name of a ValueType.
func ValueTypeName(t ValueType) string {
	if t.IsConcreteRef() {
		if t.IsNullable() {
			return fmt.Sprintf("(ref null %d)", t.TypeIndex())
		}
		return fmt.Sprintf("(ref %d)", t.TypeIndex())
	}
	switch t.AsNullable() {
	case ValueTypeI32:
		return "i32"
	case ValueTypeI64:
		return "i64"
	case ValueTypeF32:
		return "f32"
	case ValueTypeF64:
		return "f64"
	case ValueTypeV128:
		return "v128"
	case ValueTypeFuncref:
		if !t.IsNullable() {
			return "(ref func)"
		}
		return "funcref"
	case ValueTypeExternref:
		if !t.IsNullable() {
			return "(ref extern)"
		}
		return "externref"
	case ValueTypeExnref:
		if !t.IsNullable() {
			return "(ref exn)"
		}
		return "exnref"
	}
	return "unknown"
}

func isReferenceValueType(vt ValueType) bool {
	return vt.IsRef()
}

// isRefSubtypeOf returns true if actual is a subtype of (or equal to) expected.
// Non-nullable is a subtype of nullable. Concrete function refs are subtypes of funcref.
func isRefSubtypeOf(actual, expected ValueType) bool {
	if actual == expected {
		return true
	}
	// Non-nullable is subtype of nullable (same kind/index).
	if actual.AsNullable() == expected.AsNullable() && expected.IsNullable() {
		return true
	}
	// Concrete function ref is subtype of (abstract) funcref (nullable or non-nullable).
	if actual.IsConcreteRef() && expected.Kind() == ValueTypeFuncref.Kind() {
		if !actual.IsNullable() || expected.IsNullable() {
			return true
		}
	}
	return false
}

// areRefTypesCompatible returns true if either type is a subtype of the other.
func areRefTypesCompatible(a, b ValueType) bool {
	return isRefSubtypeOf(a, b) || isRefSubtypeOf(b, a)
}

// ExternType is an alias of api.ExternType defined to simplify imports.
type ExternType = api.ExternType

const (
	ExternTypeFunc       = api.ExternTypeFunc
	ExternTypeFuncName   = api.ExternTypeFuncName
	ExternTypeTable      = api.ExternTypeTable
	ExternTypeTableName  = api.ExternTypeTableName
	ExternTypeMemory     = api.ExternTypeMemory
	ExternTypeMemoryName = api.ExternTypeMemoryName
	ExternTypeGlobal     = api.ExternTypeGlobal
	ExternTypeGlobalName = api.ExternTypeGlobalName
	ExternTypeTag        = ExternType(0x04)
	ExternTypeTagName    = "tag"
)

// ExternTypeName is an alias of api.ExternTypeName defined to simplify imports.
func ExternTypeName(t ExternType) string {
	if t == ExternTypeTag {
		return ExternTypeTagName
	}
	return api.ExternTypeName(t)
}
