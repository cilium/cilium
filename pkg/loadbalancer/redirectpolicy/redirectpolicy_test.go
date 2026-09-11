// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestParseLRPRejectsEmptyBackendPorts(t *testing.T) {
	lrp := &v2.CiliumLocalRedirectPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "echo",
			Namespace: "default",
		},
		Spec: v2.CiliumLocalRedirectPolicySpec{
			RedirectFrontend: v2.RedirectFrontend{
				AddressMatcher: &v2.Frontend{
					IP: "169.254.169.254",
					ToPorts: []v2.PortInfo{{
						Port:     "80",
						Protocol: api.ProtoTCP,
					}},
				},
			},
			RedirectBackend: v2.RedirectBackend{},
		},
	}

	_, err := parseLRP(DefaultConfig, nil, lrp)
	require.Error(t, err)
}
