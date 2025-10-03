// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cookie

import "github.com/cilium/cilium/pkg/labels"

// BakedCookie tracks policy metadata such as labels, log string, etc.
type BakedCookie struct {
	Labels  labels.LabelArrayListString
	Logs    []string
	Version uint64
}

// NewBakedCookie returns a new instance.
func NewBakedCookie(labels labels.LabelArrayListString, logs []string, version uint64) *BakedCookie {
	return &BakedCookie{
		Labels:  labels,
		Logs:    logs,
		Version: version,
	}
}

// IsEmpty returns true if the cookie has no labels and no log string.
func (b *BakedCookie) IsEmpty() bool {
	return b == nil || (len(b.Logs) == 0 && b.Labels == "")
}
