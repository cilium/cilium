// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bpf

import (
	"encoding/json"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/datapath/config"
)

// applyConstants sets the values of BPF C runtime configurables defined using
// the DECLARE_CONFIG macro.
func applyConstants(spec *ebpf.CollectionSpec, obj any) error {
	if obj == nil {
		return nil
	}

	constants, err := config.Map(obj)
	if err != nil {
		return fmt.Errorf("converting struct to map: %w", err)
	}

	for name, value := range constants {
		constName := config.ConstantPrefix + name

		v, ok := spec.Variables[constName]
		if !ok {
			return fmt.Errorf("can't set non-existent Variable %s", name)
		}

		if v.SectionName != config.Section {
			return fmt.Errorf("can only set Cilium config variables in section %s (got %s:%s), ", config.Section, v.SectionName, name)
		}

		if err := v.Set(value); err != nil {
			return fmt.Errorf("setting Variable %s: %w", name, err)
		}
	}

	return nil
}

// iterAny returns a sequence that yields the elements of the given object if it
// is a slice, or the object itself otherwise. Nil values are never yielded.
func iterAny(obj any) iter.Seq[any] {
	return func(yield func(any) bool) {
		if obj == nil {
			return
		}

		if reflect.TypeOf(obj).Kind() != reflect.Slice {
			yield(obj)
			return
		}

		rv := reflect.ValueOf(obj)
		for i := 0; i < rv.Len(); i++ {
			v := rv.Index(i)
			if v.IsNil() {
				continue
			}
			if !yield(v.Interface()) {
				return
			}
		}
	}
}

// typeName returns the name of the type of the given object. If the object is
// a pointer, the name of the pointed-to type is returned.
func typeName(i any) string {
	if i == nil {
		return ""
	}
	typ := reflect.TypeOf(i)
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
	}
	return typ.String()
}

// printConstants returns a string representation of a given consts object for
// logging purposes. Since the input can be a slice of objects, they need to be
// printed separately for struct field names to show up using %#v.
func printConstants(objs any) string {
	var frags []string
	for obj := range iterAny(objs) {
		frags = append(frags, fmt.Sprintf("%#v", obj))
	}
	return "[" + strings.Join(frags, ", ") + "]"
}

// configDumpLayout defines the layout of the JSON file written by
// dumpConstants.
//
// An example of the file format is:
//
//	{
//	  "objects": [
//	    {
//	      "name": "config.BPFHost",
//	      "values": {
//	        "AllowICMPFragNeeded": true,
//	        "DeviceMTU": 1500
//	    }
//	  ],
//	  "variables": {
//	    "__config_allow_icmp_frag_needed": "AQ==",
//	    "__config_device_mtu": "3AU="
//	  }
//	}
type configDumpLayout struct {
	Objects   []objDumpLayout   `json:"objects"`
	Variables map[string][]byte `json:"variables"`
}

type objDumpLayout struct {
	Name   string `json:"name"`
	Values any    `json:"values"`
}

// dumpConstants writes the values of BPF C runtime configurables defined using
// the DECLARE_CONFIG macro to a JSON file at
// [CollectionOptions.ConfigDumpPath].
//
// This file can be used by tooling to read back the config values for
// troubleshooting purposes.
func dumpConstants(spec *ebpf.CollectionSpec, opts *CollectionOptions) error {
	if opts.ConfigDumpPath == "" {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(opts.ConfigDumpPath), 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	file, err := os.Create(opts.ConfigDumpPath)
	if err != nil {
		return fmt.Errorf("create config file: %w", err)
	}
	defer file.Close()

	// Unwrap slice of objects to obtain their type names.
	objs := make([]objDumpLayout, 0)
	for obj := range iterAny(opts.Constants) {
		objs = append(objs, objDumpLayout{typeName(obj), obj})
	}

	// Write out marshaled variable values for replaying BPF loads later.
	vars := make(map[string][]byte)
	for name, v := range spec.Variables {
		if v.SectionName != config.Section {
			continue
		}
		vars[name] = v.Value
	}

	if err := json.NewEncoder(file).Encode(configDumpLayout{
		Objects:   objs,
		Variables: vars,
	}); err != nil {
		return fmt.Errorf("dump constants: %w", err)
	}

	return nil
}
