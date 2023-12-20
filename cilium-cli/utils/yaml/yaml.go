// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"bytes"
	"io"

	"sigs.k8s.io/yaml"

	apiyaml "k8s.io/apimachinery/pkg/util/yaml"
)

func MustUnmarshal(y []byte, o interface{}, opts ...yaml.JSONOpt) {
	err := yaml.Unmarshal(y, o, opts...)
	if err != nil {
		// Developer mistake, this shouldn't happen
		panic(err)
	}
}

// MustUnmarshalMulti unmarshals a yaml document that contains
// one or more of the same type.
// Note that the returned list value may contain nils, due to a quirk in the
// yaml decoder.
func MustUnmarshalMulti[T any](y []byte) []T {
	out := []T{}
	reader := bytes.NewReader(y)
	decoder := apiyaml.NewYAMLOrJSONDecoder(reader, 4096)
	for {
		var v T
		if err := decoder.Decode(&v); err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}
		out = append(out, v)
	}
	return out
}
