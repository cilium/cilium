// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
	vUint64, err := strconv.ParseUint(value, 10, 16)
	if err != nil {
		return err
	}
	*i = append(*i, uint16(vUint64))
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
