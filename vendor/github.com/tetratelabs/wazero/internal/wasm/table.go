package wasm

import (
	"fmt"
	"math"
	"sync"

	"github.com/tetratelabs/wazero/api"
)

// Table describes the limits of elements and its type in a table.
type Table struct {
	Min      uint32
	Max      *uint32
	Type     RefType
	InitExpr *ConstantExpression
}

// RefType is a reference type used for table elements.
type RefType = ValueType

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
	OffsetExpr ConstantExpression

	// TableIndex is the table's index to which this element segment is applied.
	// Note: This is used if and only if the Mode is active.
	TableIndex Index

	// Followings are set/used regardless of the Mode.

	// Init expressions are table elements where each expression evaluates to the function index by which the module initialize the table.
	Init []ConstantExpression

	// Type holds the type of this element segment, which is the RefType in WebAssembly 2.0.
	Type RefType

	// Mode is the mode of this element segment.
	Mode ElementMode
}

// IsActive returns true if the element segment is "active" mode which requires the runtime to initialize table
// with the contents in .Init field.
func (e *ElementSegment) IsActive() bool {
	return e.Mode == ElementModeActive
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

	// The following is only used when the table is exported.

	// involvingModuleInstances is a set of module instances which are involved in the table instance.
	// This is critical for safety purpose because once a table is imported, it can hold any reference to
	// any function in the owner and importing module instances. Therefore, these module instance,
	// transitively the compiled modules, must be alive as long as the table instance is alive.
	involvingModuleInstances []*ModuleInstance
	// involvingModuleInstancesMutex is a mutex to protect involvingModuleInstances.
	involvingModuleInstancesMutex sync.RWMutex
}

// ElementInstance represents an element instance in a module.
//
// See https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/exec/runtime.html#element-instances
type ElementInstance = []Reference

// Reference is the runtime representation of RefType which is either RefTypeFuncref or RefTypeExternref.
type Reference = uintptr

// validateTable ensures any ElementSegment is valid. This caches results via Module.validatedActiveElementSegments.
// Note: limitsType are validated by decoders, so not re-validated here.
func (m *Module) validateTable(enabledFeatures api.CoreFeatures, tables []Table, maximumTableIndex uint32) error {
	if len(tables) > int(maximumTableIndex) {
		return fmt.Errorf("too many tables in a module: %d given with limit %d", len(tables), maximumTableIndex)
	}

	importedTableCount := m.ImportTableCount

	// Create bounds checks as these can err prior to instantiation
	funcCount := m.ImportFunctionCount + m.SectionElementCount(SectionIDFunction)
	globalsCount := m.ImportGlobalCount + m.SectionElementCount(SectionIDGlobal)

	// Now, we have to figure out which table elements can be resolved before instantiation and also fail early if there
	// are any imported globals that are known to be invalid by their declarations.
	for i := range m.ElementSection {
		elem := &m.ElementSection[i]
		idx := Index(i)
		initCount := uint32(len(elem.Init))

		// Any offset applied is to the element, not the function index: validate here if the funcidx is sound.
		for ei, init := range elem.Init {
			_, initType, err := evaluateConstExpr(
				&init,
				func(globalIndex Index) (ValueType, uint64, uint64, error) {
					if globalIndex >= Index(globalsCount) {
						return 0, 0, 0, fmt.Errorf("%s[%d].init[%d] global index %d out of range", SectionIDName(SectionIDElement), idx, ei, globalIndex)
					}
					vt, err := m.resolveConstExprGlobalType(enabledFeatures, SectionIDElement, idx, globalIndex)
					return vt, 0, 0, err
				},
				func(funcIndex Index) (Reference, error) {
					if funcIndex >= Index(funcCount) {
						return 0, fmt.Errorf("%s[%d].init[%d] func index %d out of range", SectionIDName(SectionIDElement), idx, ei, funcIndex)
					}
					return 0, nil
				},
			)
			if err != nil {
				return err
			}

			switch elem.Type {
			case RefTypeFuncref:
				if initType != ValueTypeFuncref {
					return fmt.Errorf("%s[%d].init[%d] must be funcref but was %s", SectionIDName(SectionIDElement), idx, ei, ValueTypeName(initType))
				}
			case RefTypeExternref:
				if initType != ValueTypeExternref {
					return fmt.Errorf("%s[%d].init[%d] must be externref but was %s", SectionIDName(SectionIDElement), idx, ei, ValueTypeName(initType))
				}
			default:
				if !isRefSubtypeOf(initType, elem.Type) && initType != ValueTypeFuncref {
					return fmt.Errorf("%s[%d].init[%d] must be %s but was %s",
						SectionIDName(SectionIDElement), idx, ei, ValueTypeName(elem.Type), ValueTypeName(initType))
				}
			}
		}

		if elem.IsActive() {
			if len(tables) <= int(elem.TableIndex) {
				return fmt.Errorf("unknown table %d as active element target", elem.TableIndex)
			}

			t := tables[elem.TableIndex]
			if !isRefSubtypeOf(elem.Type, t.Type) {
				return fmt.Errorf("element type mismatch: table has %s but element has %s",
					RefTypeName(t.Type), RefTypeName(elem.Type),
				)
			}

			hasGlobalRef := false

			offsetExprResults, offsetExprType, err := evaluateConstExpr(
				&elem.OffsetExpr,
				func(globalIndex Index) (ValueType, uint64, uint64, error) {
					hasGlobalRef = true

					if globalIndex >= Index(globalsCount) {
						return 0, 0, 0, fmt.Errorf("%s[%d] global index %d out of range", SectionIDName(SectionIDElement), idx, globalIndex)
					}

					vt, err := m.resolveConstExprGlobalType(enabledFeatures, SectionIDElement, idx, globalIndex)
					if err != nil {
						return 0, 0, 0, err
					}

					if vt != ValueTypeI32 {
						return 0, 0, 0, fmt.Errorf("%s[%d] (global.get %d): import[%d].global.ValType != i32", SectionIDName(SectionIDElement), idx, globalIndex, i)
					}
					return ValueTypeI32, 0, 0, nil
				},
				func(funcIndex Index) (Reference, error) {
					return 0, nil
				},
			)
			if err != nil {
				return fmt.Errorf("%s[%d] couldn't evaluate offset expression: %w", SectionIDName(SectionIDElement), idx, err)
			}
			if offsetExprType != ValueTypeI32 {
				return fmt.Errorf("%s[%d] offset expression must return i32 but was %s", SectionIDName(SectionIDElement), idx, ValueTypeName(offsetExprType))
			}

			if !enabledFeatures.IsEnabled(api.CoreFeatureReferenceTypes) && !hasGlobalRef && elem.TableIndex >= importedTableCount {
				offset := uint32(offsetExprResults[0])
				if err = checkSegmentBounds(t.Min, uint64(initCount)+uint64(offset), idx); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// buildTable returns TableInstances if the module defines or imports a table.
//   - importedTables: returned as `tables` unmodified.
//   - importedGlobals: include all instantiated, imported globals.
//
// If the result `init` is non-nil, it is the `tableInit` parameter of Engine.NewModuleEngine.
//
// Note: An error is only possible when an ElementSegment.OffsetExpr is out of range of the TableInstance.Min.
func (m *ModuleInstance) buildTables(module *Module, skipBoundCheck bool) (err error) {
	idx := module.ImportTableCount
	for i := range module.TableSection {
		tsec := &module.TableSection[i]
		t := &TableInstance{
			References: make([]Reference, tsec.Min), Min: tsec.Min, Max: tsec.Max,
			Type: tsec.Type,
		}
		if tsec.InitExpr != nil {
			initVals := evaluateConstExprInModuleInstance(tsec.InitExpr, m)
			if len(initVals) > 0 && initVals[0] != 0 {
				initRef := Reference(initVals[0])
				for j := range t.References {
					t.References[j] = initRef
				}
			}
		}
		m.Tables[idx] = t
		idx++
	}

	if !skipBoundCheck {
		for elemI := range module.ElementSection { // Do not loop over the value since elementSegments is a slice of value.
			elem := &module.ElementSection[elemI]
			table := m.Tables[elem.TableIndex]
			offset := uint32(evaluateConstExprInModuleInstance(&elem.OffsetExpr, m)[0])
			// Check to see if we are out-of-bounds
			initCount := uint64(len(elem.Init))
			if err = checkSegmentBounds(table.Min, uint64(offset)+initCount, Index(elemI)); err != nil {
				return
			}
		}
	}
	return
}

// checkSegmentBounds fails if the capacity needed for an ElementSegment.Init is larger than limitsType.Min
//
// WebAssembly 1.0 (20191205) doesn't forbid growing to accommodate element segments, and spectests are inconsistent.
// For example, the spectests enforce elements within Table limitsType.Min, but ignore Import.DescTable min. What this
// means is we have to delay offset checks on imported tables until we link to them.
// e.g. https://github.com/WebAssembly/spec/blob/wg-1.0/test/core/elem.wast#L117 wants pass on min=0 for import
// e.g. https://github.com/WebAssembly/spec/blob/wg-1.0/test/core/elem.wast#L142 wants fail on min=0 module-defined
func checkSegmentBounds(min uint32, requireMin uint64, idx Index) error { // uint64 in case offset was set to -1
	if requireMin > uint64(min) {
		return fmt.Errorf("%s[%d].init exceeds min table size", SectionIDName(SectionIDElement), idx)
	}
	return nil
}

// Grow appends the `initialRef` by `delta` times into the References slice.
// Returns -1 if the operation is not valid, otherwise the old length of the table.
//
// https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/exec/instructions.html#xref-syntax-instructions-syntax-instr-table-mathsf-table-grow-x
func (t *TableInstance) Grow(delta uint32, initialRef Reference) (currentLen uint32) {
	currentLen = uint32(len(t.References))
	if delta == 0 {
		return
	}

	if newLen := int64(currentLen) + int64(delta); // adding as 64bit ints to avoid overflow.
	newLen >= math.MaxUint32 || (t.Max != nil && newLen > int64(*t.Max)) {
		return 0xffffffff // = -1 in signed 32-bit integer.
	}

	t.References = append(t.References, make([]uintptr, delta)...)
	if initialRef == 0 {
		return
	}

	// Uses the copy trick for faster filling the new region with the initial value.
	// https://github.com/golang/go/blob/go1.24.0/src/slices/slices.go#L514-L517
	newRegion := t.References[currentLen:]
	newRegion[0] = initialRef
	for i := 1; i < len(newRegion); i *= 2 {
		copy(newRegion[i:], newRegion[:i])
	}
	return
}
