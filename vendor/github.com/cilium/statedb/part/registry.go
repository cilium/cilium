// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package part

import (
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"sync"
	"unicode/utf8"
)

// keyTypeRegistry is a registry of functions to convert to/from keys (of type K).
// This mechanism enables use of zero value and JSON marshalling and unmarshalling
// with Map and Set.
var keyTypeRegistry sync.Map // map[reflect.Type]func(K) []byte

// RegisterKeyType registers a new key type to be used with the Map and Set types.
// Intended to be called from init() functions.
// For Set-only usage only the [bytesFromKey] function is needed.
func RegisterKeyType[K any](bytesFromKey func(K) []byte) {
	keyType := reflect.TypeFor[K]()
	keyTypeRegistry.Store(
		keyType,
		bytesFromKey,
	)
}

func lookupKeyType[K any]() func(K) []byte {
	keyType := reflect.TypeFor[K]()
	funcAny, ok := keyTypeRegistry.Load(keyType)
	if !ok {
		panic(fmt.Sprintf("Key type %q not registered with part.RegisterMapKeyType()", keyType))
	}
	return funcAny.(func(K) []byte)
}

func init() {
	// Register common key types.
	RegisterKeyType[string](func(s string) []byte { return []byte(s) })
	RegisterKeyType[[]byte](func(b []byte) []byte { return b })
	RegisterKeyType[byte](func(b byte) []byte { return []byte{b} })
	RegisterKeyType[rune](func(r rune) []byte { return utf8.AppendRune(nil, r) })
	RegisterKeyType[complex128](func(c complex128) []byte {
		buf := make([]byte, 0, 16)
		buf = binary.BigEndian.AppendUint64(buf, math.Float64bits(real(c)))
		buf = binary.BigEndian.AppendUint64(buf, math.Float64bits(imag(c)))
		return buf
	})
	RegisterKeyType[float64](func(x float64) []byte { return binary.BigEndian.AppendUint64(nil, math.Float64bits(x)) })
	RegisterKeyType[float32](func(x float32) []byte { return binary.BigEndian.AppendUint32(nil, math.Float32bits(x)) })
	RegisterKeyType[uint64](func(x uint64) []byte { return binary.BigEndian.AppendUint64(nil, x) })
	RegisterKeyType[uint32](func(x uint32) []byte { return binary.BigEndian.AppendUint32(nil, x) })
	RegisterKeyType[uint16](func(x uint16) []byte { return binary.BigEndian.AppendUint16(nil, x) })
	RegisterKeyType[int64](func(x int64) []byte { return binary.BigEndian.AppendUint64(nil, uint64(x)) })
	RegisterKeyType[int32](func(x int32) []byte { return binary.BigEndian.AppendUint32(nil, uint32(x)) })
	RegisterKeyType[int16](func(x int16) []byte { return binary.BigEndian.AppendUint16(nil, uint16(x)) })
	RegisterKeyType[int](func(x int) []byte { return binary.BigEndian.AppendUint64(nil, uint64(x)) })

	var (
		trueBytes  = []byte{'T'}
		falseBytes = []byte{'F'}
	)
	RegisterKeyType[bool](func(b bool) []byte {
		if b {
			return trueBytes
		} else {
			return falseBytes
		}
	})

}
