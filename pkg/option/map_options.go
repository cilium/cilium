// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"fmt"
	"strings"
)

// Validator validates the option string.
type Validator func(val string) error

// MapOptions holds a map of values and a validation function.
type MapOptions struct {
	vals map[string]string
	// Validators must validate individual "key=value" entries
	// within the map.
	validators []Validator
}

// NewMapOptions creates a reference to a new MapOptions struct.
func NewMapOptions(values *map[string]string, validators ...Validator) *MapOptions {
	if *values == nil {
		*values = make(map[string]string)
	}

	return &MapOptions{
		vals:       *values,
		validators: validators,
	}
}

func (opts *MapOptions) String() string {
	var kvs []string
	for k, v := range opts.vals {
		kvs = append(kvs, fmt.Sprintf("%s=%s", k, v))
	}
	return strings.Join(kvs, ",")
}

// Type returns a string name for this Option type
func (opts *MapOptions) Type() string {
	return "map"
}

// Set validates, if needed, the input value and adds it to the internal map.
// It splits the input string by ',' and then by '=' to create key-value pairs.
func (opts *MapOptions) Set(value string) error {
	for kv := range strings.SplitSeq(value, ",") {
		for _, validator := range opts.validators {
			if err := validator(kv); err != nil {
				return err
			}
		}

		vals := strings.SplitN(kv, "=", 2)
		if len(vals) == 1 {
			opts.vals[vals[0]] = ""
		} else {
			opts.vals[vals[0]] = vals[1]
		}
	}
	return nil
}
