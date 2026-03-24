// SPDX-License-Identifier: MIT
// Copyright (c) 2014 Derek Parker
// Original from https://github.com/go-delve/delve/tree/v1.26.1/pkg/dwarf/op

package op

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/cilium/cilium/tools/stackwhere/dwarf/leb128"
)

type Opcode byte

type Operation struct {
	Opcode Opcode
	Args   []any
}

func regnumToName(regnum uint64) string {
	return fmt.Sprintf("R%d", regnum)
}

func (op Operation) String() string {
	out := &strings.Builder{}
	if name, hasname := opcodeName[op.Opcode]; hasname {
		io.WriteString(out, name)
		if op.Opcode >= DW_OP_reg0 && op.Opcode <= DW_OP_reg31 {
			fmt.Fprintf(out, "(%s)", regnumToName(uint64(op.Opcode-DW_OP_reg0)))
		} else if op.Opcode >= DW_OP_breg0 && op.Opcode <= DW_OP_breg31 {
			fmt.Fprintf(out, "(%s)", regnumToName(uint64(op.Opcode-DW_OP_breg0)))
		}
		out.Write([]byte{' '})
	} else {
		fmt.Fprintf(out, "%#x ", op.Opcode)
	}

	for i, arg := range op.Args {
		switch v := arg.(type) {
		case uint64:
			fmt.Fprintf(out, "%#x ", v)
		case int64:
			fmt.Fprintf(out, "%#x ", v)
		case []byte:
			fmt.Fprintf(out, "%d [%x] ", len(v), v)
		default:
			fmt.Fprintf(out, "%v ", v)
		}
		if (op.Opcode == DW_OP_regx || op.Opcode == DW_OP_bregx) && i == 0 {
			if regnum, ok := arg.(uint64); ok {
				fmt.Fprintf(out, "(%s)", regnumToName(regnum))
			}
		}
	}

	return out.String()
}

func Parse(instructions []byte) ([]Operation, error) {
	in := bytes.NewBuffer(instructions)

	var ops []Operation
	for {
		opcode, err := in.ReadByte()
		if err != nil {
			break
		}
		op := Operation{
			Opcode: Opcode(opcode),
		}
		for _, arg := range opcodeArgs[Opcode(opcode)] {
			var err error
			switch arg {
			case 's':
				var n int64
				n, _, err = leb128.DecodeSigned(in)
				op.Args = append(op.Args, n)
			case 'u':
				var n uint64
				n, _, err = leb128.DecodeUnsigned(in)
				op.Args = append(op.Args, n)
			case '1':
				var x uint8
				binary.Read(in, binary.LittleEndian, &x)
				op.Args = append(op.Args, x)
			case '2':
				var x uint16
				binary.Read(in, binary.LittleEndian, &x)
				op.Args = append(op.Args, x)
			case '4':
				var x uint32
				binary.Read(in, binary.LittleEndian, &x)
				op.Args = append(op.Args, x)
			case '8':
				var x uint64
				binary.Read(in, binary.LittleEndian, &x)
				op.Args = append(op.Args, x)
			case 'B':
				var sz uint64
				sz, _, err = leb128.DecodeUnsigned(in)
				data := make([]byte, sz)
				sz2, _ := in.Read(data)
				data = data[:sz2]
				op.Args = append(op.Args, data)
			}
			if err != nil {
				return nil, fmt.Errorf("error parsing DWARF op %s: %w", op.String(), err)
			}
		}
		ops = append(ops, op)
	}

	return ops, nil
}
