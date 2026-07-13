// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkpolicy

import (
	"context"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestValidateCNPEndpointSelectorNamespace(t *testing.T) {
	testCases := []struct {
		name        string
		namespace   string
		matchLabels map[string]string
		wantErr     bool
	}{
		{
			name:        "selector matches another namespace",
			namespace:   "foo",
			matchLabels: map[string]string{"k8s:io.kubernetes.pod.namespace": "bar"},
			wantErr:     true,
		},
		{
			name:        "selector matches own namespace",
			namespace:   "foo",
			matchLabels: map[string]string{"k8s:io.kubernetes.pod.namespace": "foo"},
			wantErr:     false,
		},
		{
			name:        "selector without namespace match",
			namespace:   "foo",
			matchLabels: map[string]string{"app": "demo-app"},
			wantErr:     false,
		},
		{
			name:        "unprefixed namespace key matching another namespace",
			namespace:   "foo",
			matchLabels: map[string]string{"io.kubernetes.pod.namespace": "bar"},
			wantErr:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			spec := &api.Rule{
				EndpointSelector: api.EndpointSelector{
					LabelSelector: &slim_metav1.LabelSelector{
						MatchLabels: tc.matchLabels,
					},
				},
				Ingress: []api.IngressRule{{}},
			}
			require.NoError(t, spec.ValidateAndSanitize())

			err := validateCNPEndpointSelectorNamespace(tc.namespace, spec)
			if tc.wantErr {
				require.Error(t, err)
				require.ErrorContains(t, err, "CiliumNetworkPolicy")
				require.ErrorContains(t, err, "endpointSelector")
				require.ErrorContains(t, err, "namespace")
			} else {
				require.NoError(t, err)
			}
		})
	}

	t.Run("nil spec", func(t *testing.T) {
		require.NoError(t, validateCNPEndpointSelectorNamespace("foo", nil))
	})

	t.Run("nil endpoint selector", func(t *testing.T) {
		spec := &api.Rule{
			Ingress: []api.IngressRule{{}},
		}
		require.NoError(t, validateCNPEndpointSelectorNamespace("foo", spec))
	})

	t.Run("matchExpressions In with multiple namespaces", func(t *testing.T) {
		spec := &api.Rule{
			EndpointSelector: api.EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchExpressions: []slim_metav1.LabelSelectorRequirement{
						{
							Key:      "k8s:io.kubernetes.pod.namespace",
							Operator: slim_metav1.LabelSelectorOpIn,
							Values:   []string{"foo", "bar"},
						},
					},
				},
			},
			Ingress: []api.IngressRule{{}},
		}
		require.NoError(t, spec.ValidateAndSanitize())
		require.Error(t, validateCNPEndpointSelectorNamespace("foo", spec))
	})
}
func testValidator(t *testing.T) *policyValidator {
	t.Helper()

	logger := hivetest.Logger(t)
	_, cs := k8s_client.NewFakeClientset(logger)

	return &policyValidator{
		params: &ValidatorParams{
			Logger:    logger,
			Clientset: cs,
			Cfg:       defaultConfig,
		},
	}
}

// validCondition returns the status of the "Valid" condition and its message.
func validCondition(t *testing.T, conds []cilium_api_v2.NetworkPolicyCondition) (corev1.ConditionStatus, string) {
	t.Helper()

	for _, cond := range conds {
		if cond.Type == cilium_api_v2.PolicyConditionValid {
			return cond.Status, cond.Message
		}
	}
	t.Fatalf("no %q condition found in %v", cilium_api_v2.PolicyConditionValid, conds)
	return "", ""
}

// runCNPValidation runs the CNP validator against the given policy and returns
// the resulting status conditions.
func runCNPValidation(t *testing.T, cnp *cilium_api_v2.CiliumNetworkPolicy) []cilium_api_v2.NetworkPolicyCondition {
	t.Helper()

	pv := testValidator(t)

	created, err := pv.params.Clientset.CiliumV2().CiliumNetworkPolicies(cnp.Namespace).Create(
		t.Context(), cnp, metav1.CreateOptions{})
	require.NoError(t, err)

	err = pv.handleCNPEvent(t.Context(), resource.Event[*cilium_api_v2.CiliumNetworkPolicy]{
		Kind:   resource.Upsert,
		Object: created,
		Done:   func(error) {},
	})
	require.NoError(t, err)

	updated, err := pv.params.Clientset.CiliumV2().CiliumNetworkPolicies(cnp.Namespace).Get(
		t.Context(), cnp.Name, metav1.GetOptions{})
	require.NoError(t, err)

	return updated.Status.Conditions
}

func ingressRule() []api.IngressRule {
	return []api.IngressRule{{
		IngressCommonRule: api.IngressCommonRule{
			FromEntities: api.EntitySlice{api.EntityCluster},
		},
	}}
}

// TestCNPNodeSelectorMarkedInvalid asserts that a CiliumNetworkPolicy using a
// nodeSelector is reported as invalid. The agent rejects such policies in
// CiliumNetworkPolicy.Parse ("rule cannot have NodeSelector"), so the operator
// must not report them as valid.
func TestCNPNodeSelectorMarkedInvalid(t *testing.T) {
	for _, tc := range []struct {
		name string
		cnp  *cilium_api_v2.CiliumNetworkPolicy
	}{
		{
			name: "spec",
			cnp: &cilium_api_v2.CiliumNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "host-policy", Namespace: "foo"},
				Spec: &api.Rule{
					NodeSelector: api.NewESFromLabels(),
					Ingress:      ingressRule(),
				},
			},
		},
		{
			name: "specs",
			cnp: &cilium_api_v2.CiliumNetworkPolicy{
				ObjectMeta: metav1.ObjectMeta{Name: "host-policy", Namespace: "foo"},
				Specs: api.Rules{{
					NodeSelector: api.NewESFromLabels(),
					Ingress:      ingressRule(),
				}},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, msg := validCondition(t, runCNPValidation(t, tc.cnp))
			assert.Equal(t, corev1.ConditionFalse, status)
			assert.Contains(t, msg, "cannot have NodeSelector")
		})
	}
}

// TestCNPEndpointSelectorStillValid asserts the nodeSelector check does not
// reject regular namespaced policies.
func TestCNPEndpointSelectorStillValid(t *testing.T) {
	cnp := &cilium_api_v2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-cluster", Namespace: "foo"},
		Spec: &api.Rule{
			EndpointSelector: api.NewESFromLabels(),
			Ingress:          ingressRule(),
		},
	}

	status, msg := validCondition(t, runCNPValidation(t, cnp))
	assert.Equal(t, corev1.ConditionTrue, status)
	assert.Equal(t, "Policy validation succeeded", msg)
}

// TestCCNPNodeSelectorStillValid asserts that CiliumClusterwideNetworkPolicy
// keeps supporting nodeSelector (host policies).
func TestCCNPNodeSelectorStillValid(t *testing.T) {
	pv := testValidator(t)

	ccnp := &cilium_api_v2.CiliumClusterwideNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "host-policy"},
		Spec: &api.Rule{
			NodeSelector: api.NewESFromLabels(),
			Ingress:      ingressRule(),
		},
	}

	createdCCNP, err := pv.params.Clientset.CiliumV2().CiliumClusterwideNetworkPolicies().Create(
		context.Background(), ccnp, metav1.CreateOptions{})
	require.NoError(t, err)

	err = pv.handleCCNPEvent(t.Context(), resource.Event[*cilium_api_v2.CiliumClusterwideNetworkPolicy]{
		Kind:   resource.Upsert,
		Object: createdCCNP,
		Done:   func(error) {},
	})
	require.NoError(t, err)

	updated, err := pv.params.Clientset.CiliumV2().CiliumClusterwideNetworkPolicies().Get(
		context.Background(), ccnp.Name, metav1.GetOptions{})
	require.NoError(t, err)

	status, msg := validCondition(t, updated.Status.Conditions)
	assert.Equal(t, corev1.ConditionTrue, status)
	assert.Equal(t, "Policy validation succeeded", msg)
}
