// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"github.com/cilium/cilium/pkg/identity/key"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
)

func GetCIDKeyFromK8sLabels(k8sLabels map[string]string) *key.GlobalIdentity {
	lbls := labels.Map2Labels(k8sLabels, labels.LabelSourceK8s)
	idLabels, _ := labelsfilter.Filter(lbls)
	return &key.GlobalIdentity{LabelArray: idLabels.LabelArray()}
}
