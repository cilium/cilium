// Copyright (C) 2026 The GoBGP Authors.
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

package oc

import (
	"errors"
	"math"
	"reflect"

	"github.com/go-viper/mapstructure/v2"
)

// errValueOutOfRange matches the wording mapstructure uses when it parses a
// string into an integer, so that both paths report the same problem the same
// way.
var errValueOutOfRange = errors.New("value out of range")

// integerRangeHookFunc rejects a config value that does not fit the target
// integer type.
//
// mapstructure stores an integer with reflect.Value.SetInt or SetUint, and both
// truncate without an error. With viper's WeaklyTypedInput a negative value is
// stored in an unsigned field as well. Without this hook "as = 4294967296"
// becomes 0, "as = -1" becomes 4294967295 and "tcp-mss = 70000" becomes 4464.
//
// Only integer input is checked. mapstructure parses a string with
// strconv.Parse{Int,Uint} and passes the target width, so that path already
// reports an out of range value. Float and bool input are left alone; they go
// through the same weak conversion but are not worth breaking existing configs
// for.
func integerRangeHookFunc() mapstructure.DecodeHookFuncValue {
	return func(from, to reflect.Value) (any, error) {
		if !from.IsValid() || !to.IsValid() {
			return nil, nil
		}
		data := from.Interface()

		var bits int
		var signed bool
		switch to.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			bits, signed = to.Type().Bits(), true
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			bits = to.Type().Bits()
		default:
			return data, nil
		}

		var fits bool
		switch from.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			v := from.Int()
			if signed {
				fits = fitsInt(v, bits)
			} else {
				fits = v >= 0 && fitsUint(uint64(v), bits)
			}
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			v := from.Uint()
			if signed {
				fits = v <= math.MaxInt64 && fitsInt(int64(v), bits)
			} else {
				fits = fitsUint(v, bits)
			}
		default:
			return data, nil
		}
		if !fits {
			return nil, &mapstructure.ParseError{
				Expected: to,
				Value:    data,
				Err:      errValueOutOfRange,
			}
		}
		return data, nil
	}
}

func fitsInt(v int64, bits int) bool {
	if bits >= 64 {
		return true
	}
	limit := int64(1) << (bits - 1)
	return v >= -limit && v < limit
}

func fitsUint(v uint64, bits int) bool {
	if bits >= 64 {
		return true
	}
	return v < uint64(1)<<bits
}
