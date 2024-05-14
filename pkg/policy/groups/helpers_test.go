// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package groups

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
)

func getSamplePolicy(name, ns string) *cilium_v2.CiliumNetworkPolicy {
	cnp := &cilium_v2.CiliumNetworkPolicy{}

	cnp.ObjectMeta.Name = name
	cnp.ObjectMeta.Namespace = ns
	cnp.ObjectMeta.UID = types.UID("123")
	cnp.Spec = &api.Rule{
		EndpointSelector: api.EndpointSelector{
			LabelSelector: &slim_metav1.LabelSelector{
				MatchLabels: map[string]string{
					"test": "true",
				},
			},
		},
	}
	return cnp
}

func TestCorrectDerivativeName(t *testing.T) {
	name := "test"
	cnp := getSamplePolicy(name, "testns")
	cnpDerivedPolicy, err := createDerivativeCNP(context.TODO(), cnp)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%s-groups-%s", name, cnp.ObjectMeta.UID), cnpDerivedPolicy.ObjectMeta.Name)

	// Test clusterwide policy helper functions
	ccnpName := "ccnp-test"
	ccnp := getSamplePolicy(ccnpName, "")
	ccnpDerivedPolicy, err := createDerivativeCCNP(context.TODO(), ccnp)

	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%s-groups-%s", ccnpName, ccnp.ObjectMeta.UID), ccnpDerivedPolicy.ObjectMeta.Name)
}

func TestDerivativePoliciesAreDeletedIfNogroups(t *testing.T) {
	egressRule := []api.EgressRule{
		{
			ToPorts: []api.PortRule{
				{
					Ports: []api.PortProtocol{
						{Port: "5555"},
					},
				},
			},
		},
	}

	name := "test"
	cnp := getSamplePolicy(name, "testns")

	cnp.Spec.Egress = egressRule

	cnpDerivedPolicy, err := createDerivativeCNP(context.TODO(), cnp)
	require.NoError(t, err)
	require.EqualValues(t, cnp.Spec.Egress, cnpDerivedPolicy.Specs[0].Egress)
	require.Equal(t, 1, len(cnpDerivedPolicy.Specs))

	// Clusterwide policies
	ccnpName := "ccnp-test"
	ccnp := getSamplePolicy(ccnpName, "")
	ccnp.Spec.Egress = egressRule

	ccnpDerivedPolicy, err := createDerivativeCCNP(context.TODO(), ccnp)
	require.NoError(t, err)
	require.EqualValues(t, ccnp.Spec.Egress, ccnpDerivedPolicy.Specs[0].Egress)
	require.Equal(t, 1, len(ccnpDerivedPolicy.Specs))
}

func TestDerivativePoliciesAreInheritCorrectly(t *testing.T) {
	cb := func(ctx context.Context, group *api.Groups) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.168.1.1")}, nil
	}

	egressRule := []api.EgressRule{
		{
			ToPorts: []api.PortRule{
				{
					Ports: []api.PortProtocol{
						{Port: "5555"},
					},
				},
			},
			EgressCommonRule: api.EgressCommonRule{
				ToGroups: []api.Groups{
					{
						AWS: &api.AWSGroup{
							Labels: map[string]string{
								"test": "a",
							},
						},
					},
				},
			},
		},
	}

	api.RegisterToGroupsProvider(api.AWSProvider, cb)

	name := "test"
	cnp := getSamplePolicy(name, "testns")

	cnp.Spec.Egress = egressRule

	cnpDerivedPolicy, err := createDerivativeCNP(context.TODO(), cnp)
	require.NoError(t, err)
	require.Nil(t, cnpDerivedPolicy.Spec)
	require.Len(t, cnpDerivedPolicy.Specs, 1)
	require.EqualValues(t, cnp.Spec.Egress[0].ToPorts, cnpDerivedPolicy.Specs[0].Egress[0].ToPorts)
	require.Len(t, cnpDerivedPolicy.Specs[0].Egress[0].ToGroups, 0)

	// Clusterwide policies
	ccnpName := "ccnp-test"
	ccnp := getSamplePolicy(ccnpName, "")
	ccnp.Spec.Egress = egressRule

	ccnpDerivedPolicy, err := createDerivativeCCNP(context.TODO(), ccnp)
	require.NoError(t, err)
	require.Nil(t, ccnpDerivedPolicy.Spec)
	require.Len(t, ccnpDerivedPolicy.Specs, 1)
	require.EqualValues(t, ccnp.Spec.Egress[0].ToPorts, ccnpDerivedPolicy.Specs[0].Egress[0].ToPorts)
	require.Len(t, ccnpDerivedPolicy.Specs[0].Egress[0].ToGroups, 0)
}
