// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"fmt"
	"io"

	"github.com/mitchellh/mapstructure"

	"github.com/cilium/cilium/pkg/safeio"

	"sigs.k8s.io/yaml"
)

// Decode attempts to decode a task configuration from a reader
// providing yaml encoded config.
func Decode(r io.Reader) (Task, error) {
	data, err := safeio.ReadAllLimit(r, safeio.MB)
	if err != nil {
		return nil, err
	}
	m := map[string]any{}
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return decodeMap(m)
}

// decodeMap decodes the map as a Base struct, in order to identify
// the kind of task to decode, then it performs a full decode.
func decodeMap(m map[string]any) (Task, error) {
	if m == nil {
		return nil, fmt.Errorf("cannot decode nil map")
	}
	result := &base{}
	mdec, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Result: &result,
	})
	if err != nil {
		return nil, err
	}
	if err := mdec.Decode(m); err != nil {
		return nil, err
	}
	switch result.Kind {
	case KindDir:
		var ts []Task
		if tm, ok := m["Tasks"]; ok {
			var objs []map[string]any
			if err := mapstructure.Decode(tm, &objs); err != nil {
				return nil, err
			}
			for _, obj := range objs {
				t, err := decodeMap(obj)
				if err != nil {
					return nil, err
				}
				ts = append(ts, t)
			}
		}
		return &Dir{
			base:  *result,
			Tasks: ts,
		}, nil
	case KindExec:
		e := &Exec{}
		return e, mapstructure.Decode(m, &e)
	case KindFile:
		f := &File{}
		return f, mapstructure.Decode(m, &f)
	case KindRequest:
		r := &Request{}
		return r, mapstructure.Decode(m, &r)
	default:
		return nil, fmt.Errorf("got unexpected object kind: %q, should be one of: %v: %q", result.Kind, []Kind{KindDir, KindExec, KindFile, KindRequest}, m)
	}
}
