// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dump

import (
	"fmt"
	"io"
	"io/ioutil"

	"github.com/mitchellh/mapstructure"
	"gopkg.in/yaml.v2"
)

// Kind is used to declare a tasks type when encoding/decoding.

// All tasks should declare their type using Kind.
type Kind string

const (
	KindDir     Kind = "Dir"
	KindExec    Kind = "Exec"
	KindRequest Kind = "Request"
	KindFile    Kind = "File"
	KindBPFMap  Kind = "BPFMap"
)

// Decode attempts to decode a task configuration from a reader
// providing yaml encoded config.
func Decode(r io.Reader) (Task, error) {
	data, err := ioutil.ReadAll(r) // todo: don't use this
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
// the kind of task to decode, then it performs a full decod
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
		return decodeObj[Exec](m)
	case KindFile:
		return decodeObj[File](m)
	case KindRequest:
		return decodeObj[Request](m)
	case KindBPFMap:
		tf, err := getTaskFactory(result.GetName())
		if err != nil {
			return nil, err
		}
		return tf.Create(result.GetName()), nil
	default:
		return nil, fmt.Errorf("got unexpected object kind: %q, should be one of: %v: %q", result.Kind, []Kind{KindDir, KindExec, KindFile, KindRequest}, m)
	}
}

func decodeObj[T any](m map[string]any) (*T, error) {
	var v T
	return &v, mapstructure.Decode(m, &v)
}
