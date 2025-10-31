// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cookie

import "github.com/cilium/cilium/pkg/labels"

// BakedCookie tracks policy metadata such as labels, log string, etc.
type BakedCookie struct {
	Labels labels.LabelArrayListString
	Logs   []string
}

// NewBakedCookie returns a new instance.
func NewBakedCookie(labels labels.LabelArrayListString, logs []string) *BakedCookie {
	return &BakedCookie{
		Labels: labels,
		Logs:   logs,
	}
}

// IsEmpty returns true if the cookie has no labels and no logs.
func (b *BakedCookie) IsEmpty() bool {
	return b == nil || (len(b.Logs) == 0 && !b.HasLabels())
}

func (b *BakedCookie) HasLabels() bool {
	return b != nil && (len(b.Labels) != 0 && b.Labels != "[]")
}
