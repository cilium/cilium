// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"fmt"
	"strings"
)

// Validator returns a validated string along with a possible error.
type Validator func(val string) (string, error)

// MapOptions holds a map of values and a validation function.
type MapOptions struct {
	vals map[string]string
	// Validator must validate individual "key=value" entries
	// within the map.
	validator Validator
}

// NamedMapOptions is a MapOptions struct with a configuration name.
// This struct is useful to keep reference to the assigned
// field name in the internal configuration struct.
type NamedMapOptions struct {
	name string
	MapOptions
}

// NewNamedMapOptions creates a reference to a new NamedMapOpts struct.
func NewNamedMapOptions(name string, values *map[string]string, validator Validator) *NamedMapOptions {
	return &NamedMapOptions{
		name:       name,
		MapOptions: *NewMapOpts(*values, validator),
	}
}

// NewMapOpts creates a new MapOpts with the specified map of values and an
// optional validator.
func NewMapOpts(values map[string]string, validator Validator) *MapOptions {
	if values == nil {
		values = make(map[string]string)
	}
	return &MapOptions{
		vals:      values,
		validator: validator,
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
	if opts.validator != nil {
		var kvs []string
		for _, kv := range strings.Split(value, ",") {
			v, err := opts.validator(kv)
			if err != nil {
				return err
			}

			kvs = append(kvs, v)
		}
		value = strings.Join(kvs, ",")
	}
	for _, kv := range strings.Split(value, ",") {
		vals := strings.SplitN(kv, "=", 2)
		if len(vals) == 1 {
			opts.vals[vals[0]] = ""
		} else {
			opts.vals[vals[0]] = vals[1]
		}
	}
	return nil
}
