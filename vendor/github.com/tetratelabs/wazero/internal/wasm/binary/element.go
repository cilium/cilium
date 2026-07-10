package binary

import (
	"bytes"
	"fmt"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/internal/leb128"
	"github.com/tetratelabs/wazero/internal/wasm"
)

func ensureElementKindFuncRef(r *bytes.Reader) error {
	elemKind, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("read element prefix: %w", err)
	}
	if elemKind != 0x0 { // ElemKind is fixed to 0x0 now: https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/binary/modules.html#element-section
		return fmt.Errorf("element kind must be zero but was 0x%x", elemKind)
	}
	return nil
}

func decodeElementInitValueVector(r *bytes.Reader) ([]wasm.ConstantExpression, error) {
	vs, _, err := leb128.DecodeUint32(r)
	if err != nil {
		return nil, fmt.Errorf("get size of vector: %w", err)
	}

	vec := make([]wasm.ConstantExpression, vs)
	for i := range vec {
		u32, _, err := leb128.DecodeUint32(r)
		if err != nil {
			return nil, fmt.Errorf("read function index: %w", err)
		}

		if u32 >= wasm.MaximumFunctionIndex {
			return nil, fmt.Errorf("too large function index in Element init: %d", u32)
		}
		vec[i] = wasm.NewConstantExpressionFromOpcode(wasm.OpcodeRefFunc, leb128.EncodeUint32(u32))
	}
	return vec, nil
}

func decodeElementConstExprVector(r *bytes.Reader, elemType wasm.RefType, enabledFeatures api.CoreFeatures) ([]wasm.ConstantExpression, error) {
	vs, _, err := leb128.DecodeUint32(r)
	if err != nil {
		return nil, fmt.Errorf("failed to get the size of constexpr vector: %w", err)
	}
	vec := make([]wasm.ConstantExpression, vs)
	for i := range vec {
		err := decodeConstantExpression(r, enabledFeatures, &vec[i])
		if err != nil {
			return nil, err
		}
		// Expression will be validated later since we don't yet have globals to resolve the types yet.

	}
	return vec, nil
}

func decodeElementRefType(r *bytes.Reader) (wasm.RefType, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, fmt.Errorf("read element ref type: %w", err)
	}
	switch b {
	case wasm.RefPrefixNullable, wasm.RefPrefixNonNullable:
		return decodeRefType(r, b == wasm.RefPrefixNullable)
	default:
		ret := wasm.ValueType(b)
		if ret != wasm.RefTypeFuncref && ret != wasm.RefTypeExternref {
			return 0, fmt.Errorf("invalid ref type for element: 0x%x", b)
		}
		return ret, nil
	}
}

const (
	// The prefix is explained at https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/binary/modules.html#element-section

	// elementSegmentPrefixLegacy is the legacy prefix and is only valid one before CoreFeatureBulkMemoryOperations.
	elementSegmentPrefixLegacy = iota
	// elementSegmentPrefixPassiveFuncrefValueVector is the passive element whose indexes are encoded as vec(varint), and reftype is fixed to funcref.
	elementSegmentPrefixPassiveFuncrefValueVector
	// elementSegmentPrefixActiveFuncrefValueVectorWithTableIndex is the same as elementSegmentPrefixPassiveFuncrefValueVector but active and table index is encoded.
	elementSegmentPrefixActiveFuncrefValueVectorWithTableIndex
	// elementSegmentPrefixDeclarativeFuncrefValueVector is the same as elementSegmentPrefixPassiveFuncrefValueVector but declarative.
	elementSegmentPrefixDeclarativeFuncrefValueVector
	// elementSegmentPrefixActiveFuncrefConstExprVector is active whoce reftype is fixed to funcref and indexes are encoded as vec(const_expr).
	elementSegmentPrefixActiveFuncrefConstExprVector
	// elementSegmentPrefixPassiveConstExprVector is passive whoce indexes are encoded as vec(const_expr), and reftype is encoded.
	elementSegmentPrefixPassiveConstExprVector
	// elementSegmentPrefixPassiveConstExprVector is active whoce indexes are encoded as vec(const_expr), and reftype and table index are encoded.
	elementSegmentPrefixActiveConstExprVector
	// elementSegmentPrefixDeclarativeConstExprVector is declarative whoce indexes are encoded as vec(const_expr), and reftype is encoded.
	elementSegmentPrefixDeclarativeConstExprVector
)

func decodeElementSegment(r *bytes.Reader, enabledFeatures api.CoreFeatures, ret *wasm.ElementSegment) error {
	prefix, _, err := leb128.DecodeUint32(r)
	if err != nil {
		return fmt.Errorf("read element prefix: %w", err)
	}

	if prefix != elementSegmentPrefixLegacy {
		if err := enabledFeatures.RequireEnabled(api.CoreFeatureBulkMemoryOperations); err != nil {
			return fmt.Errorf("non-zero prefix for element segment is invalid as %w", err)
		}
	}

	// Encoding depends on the prefix and described at https://www.w3.org/TR/2022/WD-wasm-core-2-20220419/binary/modules.html#element-section
	switch prefix {
	case elementSegmentPrefixLegacy:
		// Legacy prefix which is WebAssembly 1.0 compatible.
		err = decodeConstantExpression(r, enabledFeatures, &ret.OffsetExpr)
		if err != nil {
			return fmt.Errorf("read expr for offset: %w", err)
		}

		ret.Init, err = decodeElementInitValueVector(r)
		if err != nil {
			return err
		}

		ret.Mode = wasm.ElementModeActive
		ret.Type = wasm.RefTypeFuncref.AsNonNullable()
		return nil
	case elementSegmentPrefixPassiveFuncrefValueVector:
		// Prefix 1 requires funcref.
		if err = ensureElementKindFuncRef(r); err != nil {
			return err
		}

		ret.Init, err = decodeElementInitValueVector(r)
		if err != nil {
			return err
		}
		ret.Mode = wasm.ElementModePassive
		ret.Type = wasm.RefTypeFuncref.AsNonNullable()
		return nil
	case elementSegmentPrefixActiveFuncrefValueVectorWithTableIndex:
		ret.TableIndex, _, err = leb128.DecodeUint32(r)
		if err != nil {
			return fmt.Errorf("get size of vector: %w", err)
		}

		if ret.TableIndex != 0 {
			if err := enabledFeatures.RequireEnabled(api.CoreFeatureReferenceTypes); err != nil {
				return fmt.Errorf("table index must be zero but was %d: %w", ret.TableIndex, err)
			}
		}

		err := decodeConstantExpression(r, enabledFeatures, &ret.OffsetExpr)
		if err != nil {
			return fmt.Errorf("read expr for offset: %w", err)
		}

		// Prefix 2 requires funcref.
		if err = ensureElementKindFuncRef(r); err != nil {
			return err
		}

		ret.Init, err = decodeElementInitValueVector(r)
		if err != nil {
			return err
		}

		ret.Mode = wasm.ElementModeActive
		ret.Type = wasm.RefTypeFuncref.AsNonNullable()
		return nil
	case elementSegmentPrefixDeclarativeFuncrefValueVector:
		// Prefix 3 requires funcref.
		if err = ensureElementKindFuncRef(r); err != nil {
			return err
		}
		ret.Init, err = decodeElementInitValueVector(r)
		if err != nil {
			return err
		}
		ret.Type = wasm.RefTypeFuncref.AsNonNullable()
		ret.Mode = wasm.ElementModeDeclarative
		return nil
	case elementSegmentPrefixActiveFuncrefConstExprVector:
		err := decodeConstantExpression(r, enabledFeatures, &ret.OffsetExpr)
		if err != nil {
			return fmt.Errorf("read expr for offset: %w", err)
		}

		ret.Init, err = decodeElementConstExprVector(r, wasm.RefTypeFuncref, enabledFeatures)
		if err != nil {
			return err
		}
		ret.Mode = wasm.ElementModeActive
		ret.Type = wasm.RefTypeFuncref
		return nil
	case elementSegmentPrefixPassiveConstExprVector:
		ret.Type, err = decodeElementRefType(r)
		if err != nil {
			return err
		}
		ret.Init, err = decodeElementConstExprVector(r, ret.Type, enabledFeatures)
		if err != nil {
			return err
		}
		ret.Mode = wasm.ElementModePassive
		return nil
	case elementSegmentPrefixActiveConstExprVector:
		ret.TableIndex, _, err = leb128.DecodeUint32(r)
		if err != nil {
			return fmt.Errorf("get size of vector: %w", err)
		}

		if ret.TableIndex != 0 {
			if err := enabledFeatures.RequireEnabled(api.CoreFeatureReferenceTypes); err != nil {
				return fmt.Errorf("table index must be zero but was %d: %w", ret.TableIndex, err)
			}
		}
		err := decodeConstantExpression(r, enabledFeatures, &ret.OffsetExpr)
		if err != nil {
			return fmt.Errorf("read expr for offset: %w", err)
		}

		ret.Type, err = decodeElementRefType(r)
		if err != nil {
			return err
		}

		ret.Init, err = decodeElementConstExprVector(r, ret.Type, enabledFeatures)
		if err != nil {
			return err
		}

		ret.Mode = wasm.ElementModeActive
		return nil
	case elementSegmentPrefixDeclarativeConstExprVector:
		ret.Type, err = decodeElementRefType(r)
		if err != nil {
			return err
		}
		ret.Init, err = decodeElementConstExprVector(r, ret.Type, enabledFeatures)
		if err != nil {
			return err
		}

		ret.Mode = wasm.ElementModeDeclarative
		return nil
	default:
		return fmt.Errorf("invalid element segment prefix: 0x%x", prefix)
	}
}
