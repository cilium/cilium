// Copyright 2018 Authors of Cilium
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

package format

import (
	"strconv"
	"strings"

	"github.com/spf13/pflag"
)

// Uint16Flags is a slice of unsigned 16-bit ints with some convenience methods.
type Uint16Flags []uint16

var _ pflag.Value = &Uint16Flags{}

// String provides a human-readable string format of the received variable.
func (i *Uint16Flags) String() string {
	pieces := make([]string, 0, len(*i))
	for _, v := range *i {
		pieces = append(pieces, strconv.Itoa(int(v)))
	}
	return strings.Join(pieces, ", ")
}

// Set converts the specified value into an integer and appends it to the flags.
// Returns an error if the value cannot be converted to a 16-bit unsigned value.
func (i *Uint16Flags) Set(value string) error {
	v, err := strconv.Atoi(value)
	if err != nil {
		return err
	}
	*i = append(*i, uint16(v))
	return nil
}

// Type returns a human-readable string representing the type of the receiver.
func (i *Uint16Flags) Type() string {
	return "[]uint16"
}

// Has returns true of value exist
func (i *Uint16Flags) Has(value uint16) bool {
	for _, v := range *i {
		if v == value {
			return true
		}
	}

	return false
}
