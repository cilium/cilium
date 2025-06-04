// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/labels"
)

func TestRuleOrigin(t *testing.T) {
	lbls1 := labels.NewLabelsFromSortedList("k8s:a=1;k8s:b=1").LabelArray()
	lbls2 := labels.NewLabelsFromSortedList("k8s:a=2;k8s:b=2").LabelArray()

	ro := makeSingleRuleOrigin(lbls1)
	require.ElementsMatch(t, labels.LabelArrayList{lbls1}, ro.Value().LabelArray())

	ro = ro.Merge(makeSingleRuleOrigin(lbls2))
	require.ElementsMatch(t, labels.LabelArrayList{lbls1, lbls2}, ro.Value().LabelArray())
}
