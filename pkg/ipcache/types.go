// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
)

type labelsWithSource struct {
	labels labels.Labels
	source source.Source
}

func newLabelsWithSource(l labels.Labels, src source.Source) labelsWithSource {
	return labelsWithSource{
		source: src,
		labels: l,
	}
}

// prefixInfo holds all of the information (labels, etc.) about a given prefix
// independently based on the ResourceID of the origin of that information, and
// provides convenient accessors to consistently merge the stored information
// to generate ipcache output based on a range of inputs.
type prefixInfo map[types.ResourceID]labelsWithSource

func (s prefixInfo) ToLabels() labels.Labels {
	l := labels.NewLabelsFromModel(nil)
	for _, v := range s {
		l.MergeLabels(v.labels)
	}
	return l
}
