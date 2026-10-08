package binary

import (
	"bytes"
	"fmt"
	"io"

	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/internal/ieee754"
	"github.com/tetratelabs/wazero/internal/leb128"
	"github.com/tetratelabs/wazero/internal/wasm"
)

func decodeConstantExpression(r *bytes.Reader, enabledFeatures api.CoreFeatures, ret *wasm.ConstantExpression) error {
	lenAtStart := r.Len()
	startPos := r.Size() - int64(lenAtStart)
	for {
		opcode, err := r.ReadByte()
		if err != nil {
			return fmt.Errorf("read const expression opcode: %v", err)
		}
		switch opcode {
		case wasm.OpcodeI32Const:
			// Treat constants as signed as their interpretation is not yet known per /RATIONALE.md
			_, _, err = leb128.DecodeInt32(r)
		case wasm.OpcodeI32Add, wasm.OpcodeI32Sub, wasm.OpcodeI32Mul:
			// No immediate to read.
			if !enabledFeatures.IsEnabled(experimental.CoreFeaturesExtendedConst) {
				return fmt.Errorf("%v is not supported in a constant expression as feature \"extended-const\" is disabled", wasm.InstructionName(opcode))
			}
		case wasm.OpcodeI64Const:
			// Treat constants as signed as their interpretation is not yet known per /RATIONALE.md
			_, _, err = leb128.DecodeInt64(r)
		case wasm.OpcodeI64Add, wasm.OpcodeI64Sub, wasm.OpcodeI64Mul:
			// No immediate to read.
			if !enabledFeatures.IsEnabled(experimental.CoreFeaturesExtendedConst) {
				return fmt.Errorf("%v is not supported in a constant expression as feature \"extended-const\" is disabled", wasm.InstructionName(opcode))
			}
		case wasm.OpcodeF32Const:
			buf := make([]byte, 4)
			if _, err := io.ReadFull(r, buf); err != nil {
				return fmt.Errorf("read f32 constant: %v", err)
			}
			_, err = ieee754.DecodeFloat32(buf)
		case wasm.OpcodeF64Const:
			buf := make([]byte, 8)
			if _, err := io.ReadFull(r, buf); err != nil {
				return fmt.Errorf("read f64 constant: %v", err)
			}
			_, err = ieee754.DecodeFloat64(buf)
		case wasm.OpcodeGlobalGet:
			_, _, err = leb128.DecodeUint32(r)
		case wasm.OpcodeRefNull:
			if err := enabledFeatures.RequireEnabled(api.CoreFeatureBulkMemoryOperations); err != nil {
				return fmt.Errorf("ref.null is not supported as %w", err)
			}
			b, err := r.ReadByte()
			reftype := wasm.ValueType(b)
			if err != nil {
				return fmt.Errorf("read reference type for ref.null: %w", err)
			}
			switch reftype {
			case wasm.RefTypeFuncref, wasm.RefTypeExternref, wasm.ValueTypeExnref:
				// Valid abstract heap type.
			default:
				// Could be a concrete type index; unread the byte and try reading as LEB128.
				if err := r.UnreadByte(); err != nil {
					return fmt.Errorf("unread byte for ref.null: %w", err)
				}
				_, _, err = leb128.DecodeUint32(r)
				if err != nil {
					return fmt.Errorf("invalid type for ref.null: 0x%x", reftype)
				}
			}
		case wasm.OpcodeRefFunc:
			if err := enabledFeatures.RequireEnabled(api.CoreFeatureBulkMemoryOperations); err != nil {
				return fmt.Errorf("ref.func is not supported as %w", err)
			}
			// Parsing index.
			_, _, err = leb128.DecodeUint32(r)
		case wasm.OpcodeVecPrefix:
			if err := enabledFeatures.RequireEnabled(api.CoreFeatureSIMD); err != nil {
				return fmt.Errorf("vector instructions are not supported as %w", err)
			}
			opcode, err = r.ReadByte()
			if err != nil {
				return fmt.Errorf("read vector instruction opcode suffix: %w", err)
			}

			if opcode != wasm.OpcodeVecV128Const {
				return fmt.Errorf("invalid vector opcode for const expression: %#x", opcode)
			}

			n, err := r.Read(make([]byte, 16))
			if err != nil {
				return fmt.Errorf("read vector const instruction immediates: %w", err)
			} else if n != 16 {
				return fmt.Errorf("read vector const instruction immediates: needs 16 bytes but was %d bytes", n)
			}
		case wasm.OpcodeEnd:
			data := make([]byte, lenAtStart-(r.Len()))
			if _, err := r.ReadAt(data, startPos); err != nil {
				return fmt.Errorf("error re-buffering ConstantExpression.Data: %w", err)
			}
			ret.Data = data
			return nil
		default:
			return fmt.Errorf("%v for const expression op code: %#x", ErrInvalidByte, opcode)
		}

		if err != nil {
			return fmt.Errorf("read value: %v", err)
		}
	}
}
