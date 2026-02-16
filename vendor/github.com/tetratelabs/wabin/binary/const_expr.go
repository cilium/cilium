package binary

import (
	"bytes"
	"fmt"

	"github.com/tetratelabs/wabin/ieee754"
	"github.com/tetratelabs/wabin/leb128"
	"github.com/tetratelabs/wabin/wasm"
)

func decodeConstantExpression(r *bytes.Reader, features wasm.CoreFeatures) (*wasm.ConstantExpression, error) {
	b, err := r.ReadByte()
	if err != nil {
		return nil, fmt.Errorf("read opcode: %v", err)
	}

	remainingBeforeData := int64(r.Len())
	offsetAtData := r.Size() - remainingBeforeData

	opcode := b
	switch opcode {
	case wasm.OpcodeI32Const:
		// Treat constants as signed as their interpretation is not yet known per /RATIONALE.md
		_, _, err = leb128.DecodeInt32(r)
	case wasm.OpcodeI64Const:
		// Treat constants as signed as their interpretation is not yet known per /RATIONALE.md
		_, _, err = leb128.DecodeInt64(r)
	case wasm.OpcodeF32Const:
		_, err = ieee754.DecodeFloat32(r)
	case wasm.OpcodeF64Const:
		_, err = ieee754.DecodeFloat64(r)
	case wasm.OpcodeGlobalGet:
		_, _, err = leb128.DecodeUint32(r)
	case wasm.OpcodeRefNull:
		if err := features.RequireEnabled(wasm.CoreFeatureBulkMemoryOperations); err != nil {
			return nil, fmt.Errorf("ref.null is not supported as %w", err)
		}
		reftype, err := r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("read reference type for ref.null: %w", err)
		} else if reftype != wasm.RefTypeFuncref && reftype != wasm.RefTypeExternref {
			return nil, fmt.Errorf("invalid type for ref.null: 0x%x", reftype)
		}
	case wasm.OpcodeRefFunc:
		if err := features.RequireEnabled(wasm.CoreFeatureBulkMemoryOperations); err != nil {
			return nil, fmt.Errorf("ref.func is not supported as %w", err)
		}
		// Parsing index.
		_, _, err = leb128.DecodeUint32(r)
	case wasm.OpcodeVecPrefix:
		if err := features.RequireEnabled(wasm.CoreFeatureSIMD); err != nil {
			return nil, fmt.Errorf("vector instructions are not supported as %w", err)
		}
		opcode, err = r.ReadByte()
		if err != nil {
			return nil, fmt.Errorf("read vector instruction opcode suffix: %w", err)
		}

		if opcode != wasm.OpcodeVecV128Const {
			return nil, fmt.Errorf("invalid vector opcode for const expression: %#x", opcode)
		}

		remainingBeforeData = int64(r.Len())
		offsetAtData = r.Size() - remainingBeforeData

		n, err := r.Read(make([]byte, 16))
		if err != nil {
			return nil, fmt.Errorf("read vector const instruction immediates: %w", err)
		} else if n != 16 {
			return nil, fmt.Errorf("read vector const instruction immediates: needs 16 bytes but was %d bytes", n)
		}
	default:
		return nil, fmt.Errorf("%v for const expression opt code: %#x", ErrInvalidByte, b)
	}

	if err != nil {
		return nil, fmt.Errorf("read value: %v", err)
	}

	if b, err = r.ReadByte(); err != nil {
		return nil, fmt.Errorf("look for end opcode: %v", err)
	}

	if b != wasm.OpcodeEnd {
		return nil, fmt.Errorf("constant expression has been not terminated")
	}

	data := make([]byte, remainingBeforeData-int64(r.Len())-1)
	if _, err := r.ReadAt(data, offsetAtData); err != nil {
		return nil, fmt.Errorf("error re-buffering ConstantExpression.Data")
	}

	return &wasm.ConstantExpression{Opcode: opcode, Data: data}, nil
}

func encodeConstantExpression(expr *wasm.ConstantExpression) (ret []byte) {
	ret = append(ret, expr.Opcode)
	ret = append(ret, expr.Data...)
	ret = append(ret, wasm.OpcodeEnd)
	return
}
