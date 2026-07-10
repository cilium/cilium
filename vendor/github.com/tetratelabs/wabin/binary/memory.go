package binary

import (
	"bytes"
	"fmt"

	"github.com/tetratelabs/wabin/wasm"
)

// decodeMemory returns the wasm.Memory decoded with the WebAssembly
// Binary Format.
//
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-memory
func decodeMemory(r *bytes.Reader) (*wasm.Memory, error) {
	min, maxP, err := decodeLimitsType(r)
	if err != nil {
		return nil, err
	}

	mem := &wasm.Memory{Min: min}
	if maxP != nil {
		mem.Max = *maxP
		mem.IsMaxEncoded = true

		if min > mem.Max {
			return nil, fmt.Errorf("min %d pages (%s) > max %d pages (%s)",
				min, wasm.PagesToUnitOfBytes(min), mem.Max, wasm.PagesToUnitOfBytes(mem.Max))
		}
	}

	return mem, nil
}

// encodeMemory returns the wasm.Memory encoded in WebAssembly Binary Format.
//
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#binary-memory
func encodeMemory(i *wasm.Memory) []byte {
	maxPtr := &i.Max
	if !i.IsMaxEncoded {
		maxPtr = nil
	}
	return encodeLimitsType(i.Min, maxPtr)
}
