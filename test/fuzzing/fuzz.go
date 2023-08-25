// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build gofuzz

package fuzz

import (
	"github.com/cilium/cilium/pkg/labels"
)

func Fuzz(data []byte) int {
	label := labels.NewLabel("test", "label", "1")
	err := label.UnmarshalJSON(data)
	if err != nil {
		return 0
	}
	return 1
}
