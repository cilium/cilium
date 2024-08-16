// Copyright 2016-2017 Authors of Cilium
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

package option

import (
	"fmt"
	"strings"
)

// Validator returns a validated string along with a possible error.
type Validator func(val string) (string, error)

// MapOptions holds a map of values and a validation function.
type MapOptions struct {
	vals      map[string]string
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
	return fmt.Sprintf("%v", opts.vals)
}

// Type returns a string name for this Option type
func (opts *MapOptions) Type() string {
	return "map"
}

// Set validates, if needed, the input value and adds it to the internal map,
// by splitting on '='.
func (opts *MapOptions) Set(value string) error {
	if opts.validator != nil {
		v, err := opts.validator(value)
		if err != nil {
			return err
		}
		value = v
	}
	vals := strings.SplitN(value, "=", 2)
	if len(vals) == 1 {
		(opts.vals)[vals[0]] = ""
	} else {
		(opts.vals)[vals[0]] = vals[1]
	}
	return nil
}
