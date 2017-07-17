// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package byteorder

import (
	"encoding/binary"
	"fmt"
	"reflect"

	"github.com/vishvananda/netlink/nl"
)

// Native is set to the host ByteOrder type. This should normally be either
// BigEndian or LittleEndian.
var Native = nl.NativeEndian()

// reverse returns a reversed slice of b.
func reverse(b []byte) []byte {
	size := len(b)
	c := make([]byte, size)

	for i, j := size-1, 0; i >= 0; i, j = i-1, j+1 {
		c[j] = b[i]
	}

	return c
}

// HostToNetwork converts b to the networking byte order.
func HostToNetwork(b interface{}) interface{} {
	switch b.(type) {
	case uint16:
		return nl.Swap16(b.(uint16))
	case uint32:
		return nl.Swap32(b.(uint32))
	default:
		panic(unsupported(b))
	}
}

// NetworkToHost converts n to host byte order.
func NetworkToHost(n interface{}) interface{} {
	switch n.(type) {
	case uint16:
		return nl.Swap16(n.(uint16))
	case uint32:
		return nl.Swap32(n.(uint32))
	default:
		panic(unsupported(n))
	}
}

// HostToNetworkSlice converts b to the networking byte order.
func HostToNetworkSlice(b []byte, t reflect.Kind) interface{} {
	switch t {
	case reflect.Uint32:
		return binary.BigEndian.Uint32(b)
	case reflect.Uint16:
		return binary.BigEndian.Uint16(b)
	default:
		panic(unsupported(b))
	}
}

// HostToNetworkPut puts v into b with the networking byte order.
func HostToNetworkPut(b []byte, v interface{}) {
	switch reflect.TypeOf(v).Kind() {
	case reflect.Uint32:
		binary.BigEndian.PutUint32(b, v.(uint32))
	case reflect.Uint16:
		binary.BigEndian.PutUint16(b, v.(uint16))
	default:
		panic(unsupported(v))
	}
}

// NetworkToHostPut puts v into b with the networking byte order.
func NetworkToHostPut(b []byte, v interface{}) {
	switch reflect.TypeOf(v).Kind() {
	case reflect.Uint32:
		Native.PutUint32(b, v.(uint32))
	case reflect.Uint16:
		Native.PutUint16(b, v.(uint16))
	default:
		panic(unsupported(v))
	}
}

// HostSliceToNetwork converts b to the networking byte order.
func HostSliceToNetwork(b []byte, t reflect.Kind) interface{} {
	switch t {
	case reflect.Uint32:
		if Native != binary.BigEndian {
			return binary.BigEndian.Uint32(reverse(b))
		}
		return binary.BigEndian.Uint32(b)
	case reflect.Uint16:
		if Native != binary.BigEndian {
			return binary.BigEndian.Uint16(reverse(b))
		}
		return binary.BigEndian.Uint16(b)
	default:
		panic(unsupported(t))
	}
}

// unsupported returns a string to used for debugging unhandled types.
func unsupported(field interface{}) string {
	return fmt.Sprintf("unsupported type(%v): %v", reflect.TypeOf(field).Kind(), field)
}
