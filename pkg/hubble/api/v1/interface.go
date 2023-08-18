// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package v1

import (
	"github.com/cilium/cilium/pkg/identity"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
)

// EndpointInfo defines readable fields of a Cilium endpoint.
type EndpointInfo interface {
	GetID() uint64
	GetIdentity() identity.NumericIdentity
	GetK8sPodName() string
	GetK8sNamespace() string
	GetLabels() []string
	GetPod() *slim_corev1.Pod
	GetRealizedPolicyRuleLabelsForKey(key policy.Key) (derivedFrom labels.LabelArrayList, revision uint64, ok bool)
}
