package ieee754

import (
	"encoding/binary"
	"io"
	"math"
)

// DecodeFloat32 decodes a float32 in IEEE 754 binary representation.
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#floating-point%E2%91%A2
func DecodeFloat32(r io.Reader) (float32, error) {
	buf := make([]byte, 4)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return 0, err
	}
	raw := binary.LittleEndian.Uint32(buf)
	return math.Float32frombits(raw), nil
}

// DecodeFloat64 decodes a float64 in IEEE 754 binary representation.
// See https://www.w3.org/TR/2019/REC-wasm-core-1-20191205/#floating-point%E2%91%A2
func DecodeFloat64(r io.Reader) (float64, error) {
	buf := make([]byte, 8)
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return 0, err
	}
	raw := binary.LittleEndian.Uint64(buf)
	return math.Float64frombits(raw), nil
}
