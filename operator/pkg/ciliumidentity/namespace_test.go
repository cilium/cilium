// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"reflect"
	"testing"

	ciliumio "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slimcorev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy"
)

func TestGetNamespaceLabels(t *testing.T) {
	testCases := []struct {
		desc          string
		namespace     *slimcorev1.Namespace
		expected      labels.Labels
		expectedError error
	}{
		{
			desc: "empty_labels",
			namespace: &slimcorev1.Namespace{
				ObjectMeta: slim_metav1.ObjectMeta{
					Labels: map[string]string{},
				},
			},
			expected: labels.Map2Labels(map[string]string{}, labels.LabelSourceK8s),
		},
		{
			desc: "single_label",
			namespace: &slimcorev1.Namespace{
				ObjectMeta: slim_metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "my-app",
					},
				},
			},
			expected: labels.Map2Labels(map[string]string{
				policy.JoinPath(ciliumio.PodNamespaceMetaLabels, "app"): "my-app",
			}, labels.LabelSourceK8s),
		},
		{
			desc: "multiple_labels",
			namespace: &slimcorev1.Namespace{
				ObjectMeta: slim_metav1.ObjectMeta{
					Labels: map[string]string{
						"app":     "my-app",
						"version": "1.0",
					},
				},
			},
			expected: labels.Map2Labels(map[string]string{
				policy.JoinPath(ciliumio.PodNamespaceMetaLabels, "app"):     "my-app",
				policy.JoinPath(ciliumio.PodNamespaceMetaLabels, "version"): "1.0",
			}, labels.LabelSourceK8s),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			result := getNamespaceLabels(tc.namespace)

			if !reflect.DeepEqual(result, tc.expected) {
				t.Errorf("Expected %v, but got %v", tc.expected, result)
			}
		})
	}
}
