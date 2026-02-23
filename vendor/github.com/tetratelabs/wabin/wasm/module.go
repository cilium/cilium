package wasm

import (
	"bytes"
	"fmt"
)

// DecodeModule parses the WebAssembly Binary Format (%.wasm) into a Module. This function returns when the input is
// exhausted or an error occurs. The result can be initialized for use via Store.Instantiate.
//
// Here's a description of the return values:
// * result is the module parsed or nil on error
// * err is a FormatError invoking the parser, dangling block comments or unexpected characters.
// See binary.DecodeModule and text.DecodeModule
type DecodeModule func(
	wasm []byte,
	features CoreFeatures,
	memorySizer func(minPages uint32, maxPages *uint32) (min, capacity, max uint32),
) (result *Module, err error)

// EncodeModule encodes the given module into a byte slice depending on the format of the implementation.
// See binary.EncodeModule
type EncodeModule func(m *Module) (bytes []byte)

// The wazero specific limitation described at RATIONALE.md.
// TL;DR; We multiply by 8 (to get offsets in bytes) and the multiplication result must be less than 32bit max
const (
	MaximumGlobals       = uint32(1 << 27)
	MaximumFunctionIndex = uint32(1 << 27)
	MaximumTableIndex    = uint32(1 << 27)
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
	TypeSection []*FunctionType

	// ImportSection contains imported functions, tables, memories or globals required for instantiation
	// (Store.Instantiate).
	//
	// Note: there are no unique constraints relating to the two-level namespace of Import.Module and Import.Name.
	//
	// Note: In the Binary Format, this is SectionIDImport.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#import-section%E2%91%A0
	ImportSection []*Import

	// FunctionSection contains the index in TypeSection of each function defined in this module.
	//
	// Note: The function Index namespace begins with imported functions and ends with those defined in this module.
	// For example, if there are two imported functions and one defined in this module, the function Index 3 is defined
	// in this module at FunctionSection[0].
	//
	// Note: FunctionSection is index correlated with the CodeSection. If given the same position, ex. 2, a function
	// type is at TypeSection[FunctionSection[2]], while its locals and body are at CodeSection[2].
	//
	// Note: In the Binary Format, this is SectionIDFunction.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#function-section%E2%91%A0
	FunctionSection []Index

	// TableSection contains each table defined in this module.
	//
	// Note: The table Index namespace begins with imported tables and ends with those defined in this module.
	// For example, if there are two imported tables and one defined in this module, the table Index 3 is defined in
	// this module at TableSection[0].
	//
	// Note: Version of the WebAssembly spec allows at most one table definition per module, so the
	// length of the TableSection can be zero or one, and can only be one if there is no imported table.
	//
	// Note: In the Binary Format, this is SectionIDTable.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#table-section%E2%91%A0
	TableSection []*Table

	// MemorySection contains each memory defined in this module.
	//
	// Note: The memory Index namespace begins with imported memories and ends with those defined in this module.
	// For example, if there are two imported memories and one defined in this module, the memory Index 3 is defined in
	// this module at TableSection[0].
	//
	// Note: Version of the WebAssembly spec allows at most one memory definition per module, so the
	// length of the MemorySection can be zero or one, and can only be one if there is no imported memory.
	//
	// Note: In the Binary Format, this is SectionIDMemory.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#memory-section%E2%91%A0
	MemorySection *Memory

	// GlobalSection contains each global defined in this module.
	//
	// Global indexes are offset by any imported globals because the global index space begins with imports, followed by
	// ones defined in this module. For example, if there are two imported globals and three defined in this module, the
	// global at index 3 is defined in this module at GlobalSection[0].
	//
	// Note: In the Binary Format, this is SectionIDGlobal.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#global-section%E2%91%A0
	GlobalSection []*Global

	// ExportSection contains each export defined in this module.
	//
	// Note: In the Binary Format, this is SectionIDExport.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#exports%E2%91%A0
	ExportSection []*Export

	// StartSection is the index of a function to call before returning from Store.Instantiate.
	//
	// Note: The index here is not the position in the FunctionSection, rather in the function index namespace, which
	// begins with imported functions.
	//
	// Note: In the Binary Format, this is SectionIDStart.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#start-section%E2%91%A0
	StartSection *Index

	// Note: In the Binary Format, this is SectionIDElement.
	ElementSection []*ElementSegment

	// CodeSection is index-correlated with FunctionSection and contains each
	// function's locals and body.
	//
	// When present, the HostFunctionSection of the same index must be nil.
	//
	// Note: In the Binary Format, this is SectionIDCode.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#code-section%E2%91%A0
	CodeSection []*Code

	// Note: In the Binary Format, this is SectionIDData.
	DataSection []*DataSegment

	// DataCountSection is the optional section and holds the number of data segments in the data section.
	//
	// Note: This may exist in WebAssembly 2.0 or WebAssembly 1.0 with FeatureBulkMemoryOperations.
	// See https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/binary/modules.html#data-count-section
	// See https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/appendix/changes.html#bulk-memory-and-table-instructions
	DataCountSection *uint32

	// NameSection is set when the SectionIDCustom "name" was successfully decoded from the binary format.
	//
	// Note: This is the only SectionIDCustom defined in the WebAssembly Binary Format.
	// Others are read into CustomSections.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#name-section%E2%91%A0
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#custom-section%E2%91%A0
	NameSection *NameSection

	// CustomSections are set when the SectionIDCustom other than "name" were successfully decoded from the binary format.
	//
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#custom-section%E2%91%A0
	CustomSections []*CustomSection
}

// Index is the offset in an index namespace, not necessarily an absolute position in a Module section. This is because
// index namespaces are often preceded by a corresponding type in the Module.ImportSection.
//
// For example, the function index namespace starts with any ExternTypeFunc in the Module.ImportSection followed by
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
}

// EqualsSignature returns true if the function type has the same parameters and results.
func (f *FunctionType) EqualsSignature(params []ValueType, results []ValueType) bool {
	return bytes.Equal(f.Params, params) && bytes.Equal(f.Results, results)
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
	DescTable *Table
	// DescMem is the inlined Memory when Type equals ExternTypeMemory
	DescMem *Memory
	// DescGlobal is the inlined GlobalType when Type equals ExternTypeGlobal
	DescGlobal *GlobalType
}

// Memory describes the limits of pages (64KB) in a memory.
type Memory struct {
	Min, Max uint32
	// IsMaxEncoded true if the Max is encoded in the original source (binary or text).
	IsMaxEncoded bool
}

// Table describes the limits of elements and its type in a table.
type Table struct {
	Min  uint32
	Max  *uint32
	Type RefType
}

// RefType is either RefTypeFuncref or RefTypeExternref as of WebAssembly core 2.0.
type RefType = byte

const (
	// RefTypeFuncref represents a reference to a function.
	RefTypeFuncref = ValueTypeFuncref
	// RefTypeExternref represents a reference to a host object, which is not currently supported in wazero.
	RefTypeExternref = ValueTypeExternref
)

func RefTypeName(t RefType) (ret string) {
	switch t {
	case RefTypeFuncref:
		ret = "funcref"
	case RefTypeExternref:
		ret = "externref"
	default:
		ret = fmt.Sprintf("unknown(0x%x)", t)
	}
	return
}

// ElementMode represents a mode of element segment which is either active, passive or declarative.
//
// https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/syntax/modules.html#element-segments
type ElementMode = byte

const (
	// ElementModeActive is the mode which requires the runtime to initialize table with the contents in .Init field combined with OffsetExpr.
	ElementModeActive ElementMode = iota
	// ElementModePassive is the mode which doesn't require the runtime to initialize table, and only used with OpcodeTableInitName.
	ElementModePassive
	// ElementModeDeclarative is introduced in reference-types proposal which can be used to declare function indexes used by OpcodeRefFunc.
	ElementModeDeclarative
)

// ElementSegment are initialization instructions for a TableInstance
//
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#syntax-elem
type ElementSegment struct {
	// OffsetExpr returns the table element offset to apply to Init indices.
	// Note: This can be validated prior to instantiation unless it includes OpcodeGlobalGet (an imported global).
	// Note: This is only set when Mode is active.
	OffsetExpr *ConstantExpression

	// TableIndex is the table's index to which this element segment is applied.
	// Note: This is used if and only if the Mode is active.
	TableIndex Index

	// Followings are set/used regardless of the Mode.

	// Init indices are (nullable) table elements where each index is the function index by which the module initialize the table.
	Init []*Index

	// Type holds the type of this element segment, which is the RefType in WebAssembly 2.0.
	Type RefType

	// Mode is the mode of this element segment.
	Mode ElementMode
}

// TableInstance represents a table of (RefTypeFuncref) elements in a module.
//
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#table-instances%E2%91%A0
type TableInstance struct {
	// References holds references whose type is either RefTypeFuncref or RefTypeExternref (unsupported).
	//
	// Currently, only function references are supported.
	References []Reference

	// Min is the minimum (function) elements in this table and cannot grow to accommodate ElementSegment.
	Min uint32

	// Max if present is the maximum (function) elements in this table, or nil if unbounded.
	Max *uint32

	// Type is either RefTypeFuncref or RefTypeExternRef.
	Type RefType
}

// ElementInstance represents an element instance in a module.
//
// See https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/exec/runtime.html#element-instances
type ElementInstance struct {
	// References holds references whose type is either RefTypeFuncref or RefTypeExternref (unsupported).
	References []Reference
	// Type is the RefType of the references in this instance's References.
	Type RefType
}

// Reference is the runtime representation of RefType which is either RefTypeFuncref or RefTypeExternref.
type Reference = uintptr

type GlobalType struct {
	ValType ValueType
	Mutable bool
}

type Global struct {
	Type *GlobalType
	Init *ConstantExpression
}

type ConstantExpression struct {
	Opcode Opcode
	Data   []byte
}

// Export is the binary representation of an export indicated by Type
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-export
type Export struct {
	Type ExternType

	// Name is what the host refers to this definition as.
	Name string

	// Index is the index of the definition to export, the index namespace is by Type
	// Ex. If ExternTypeFunc, this is a position in the function index namespace.
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
}

type DataSegment struct {
	OffsetExpression *ConstantExpression
	Init             []byte
}

// NameSection represent the known custom name subsections defined in the WebAssembly Binary Format
//
// Note: This can be nil if no names were decoded for any reason including configuration.
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#name-section%E2%91%A0
type NameSection struct {
	// ModuleName is the symbolic identifier for a module. Ex. math
	//
	// Note: This can be empty for any reason including configuration.
	ModuleName string

	// FunctionNames is an association of a function index to its symbolic identifier. Ex. add
	//
	// * the key (idx) is in the function namespace, where module defined functions are preceded by imported ones.
	// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#functions%E2%91%A7
	//
	// Ex. Assuming the below text format is the second import, you would expect FunctionNames[1] = "mul"
	//	(import "Math" "Mul" (func $mul (param $x f32) (param $y f32) (result f32)))
	//
	// Note: FunctionNames are only used for debugging. At runtime, functions are called based on raw numeric index.
	// Note: This can be nil for any reason including configuration.
	FunctionNames NameMap

	// LocalNames contains symbolic names for function parameters or locals that have one.
	//
	// Note: In the Text Format, function local names can inherit parameter names from their type. Ex.
	//  * (module (import (func (param $x i32) (param i32))) (func (type 0))) = [{0, {x,0}}]
	//  * (module (import (func (param i32) (param $y i32))) (func (type 0) (local $z i32))) = [0, [{y,1},{z,2}]]
	//  * (module (func (param $x i32) (local $y i32) (local $z i32))) = [{x,0},{y,1},{z,2}]
	//
	// Note: LocalNames are only used for debugging. At runtime, locals are called based on raw numeric index.
	// Note: This can be nil for any reason including configuration.
	LocalNames IndirectNameMap
}

// CustomSection contains the name and raw data of a custom section.
type CustomSection struct {
	Name string
	Data []byte
}

// NameMap associates an index with any associated names.
//
// Note: Often the index namespace bridges multiple sections. For example, the function index namespace starts with any
// ExternTypeFunc in the Module.ImportSection followed by the Module.FunctionSection
//
// Note: NameMap is unique by NameAssoc.Index, but NameAssoc.Name needn't be unique.
// Note: When encoding in the Binary format, this must be ordered by NameAssoc.Index
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-namemap
type NameMap []*NameAssoc

type NameAssoc struct {
	Index Index
	Name  string
}

// IndirectNameMap associates an index with an association of names.
//
// Note: IndirectNameMap is unique by NameMapAssoc.Index, but NameMapAssoc.NameMap needn't be unique.
// Note: When encoding in the Binary format, this must be ordered by NameMapAssoc.Index
// https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-indirectnamemap
type IndirectNameMap []*NameMapAssoc

type NameMapAssoc struct {
	Index   Index
	NameMap NameMap
}

// SectionID identifies the sections of a Module in the WebAssembly Binary Format.
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

	// SectionIDDataCount may exist in WebAssembly 2.0 or WebAssembly 1.0 with FeatureBulkMemoryOperations enabled.
	//
	// See https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/binary/modules.html#data-count-section
	// See https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/appendix/changes.html#bulk-memory-and-table-instructions
	SectionIDDataCount
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
	}
	return "unknown"
}
