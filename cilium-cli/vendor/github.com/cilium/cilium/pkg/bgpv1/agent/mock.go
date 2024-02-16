// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

var _ policyLister = (*MockCiliumBGPPeeringPolicyLister)(nil)

type MockCiliumBGPPeeringPolicyLister struct {
	List_ func() ([]*v2alpha1.CiliumBGPPeeringPolicy, error)
}

func (m *MockCiliumBGPPeeringPolicyLister) List() ([]*v2alpha1.CiliumBGPPeeringPolicy, error) {
	return m.List_()
}
