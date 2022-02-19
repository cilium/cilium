// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of Cilium

package utils

import (
	"sigs.k8s.io/yaml"
)

func MustUnmarshalYAML(y []byte, o interface{}, opts ...yaml.JSONOpt) {
	err := yaml.Unmarshal(y, o, opts...)
	if err != nil {
		// Developer mistake, this shouldn't happen
		panic(err)
	}
}
