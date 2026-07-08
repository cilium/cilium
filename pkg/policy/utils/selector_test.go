// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestEnsureNamespaceSelector(t *testing.T) {
	for i, tc := range []struct {
		in, out api.EndpointSelector
		ns      string
	}{
		{
			in:  api.NewESFromLabels(labels.NewLabel("io.kubernetes.pod.namespace", "foo", "k8s")),
			out: api.NewESFromLabels(labels.NewLabel("io.kubernetes.pod.namespace", "foo", "k8s")),
			ns:  "bar",
		},
		{
			in:  api.NewESFromLabels(labels.NewLabel("other", "", "")),
			out: api.NewESFromLabels(labels.NewLabel("other", "", ""), labels.NewLabel("io.kubernetes.pod.namespace", "bar", "k8s")),
			ns:  "bar",
		},
		{
			in: api.NewESFromMatchRequirements(nil, []slim_metav1.LabelSelectorRequirement{{
				Key:      "io.kubernetes.pod.namespace",
				Operator: "In",
				Values:   []string{"foo"},
			}}),
			out: api.NewESFromMatchRequirements(nil, []slim_metav1.LabelSelectorRequirement{{
				Key:      "io.kubernetes.pod.namespace",
				Operator: "In",
				Values:   []string{"foo"},
			}}),
			ns: "bar",
		},
		{
			in: api.NewESFromMatchRequirements(nil, []slim_metav1.LabelSelectorRequirement{{
				Key:      "io.kubernetes.pod.namespace",
				Operator: "NotIn",
				Values:   []string{"foo"},
			}}),
			out: api.NewESFromMatchRequirements(nil, []slim_metav1.LabelSelectorRequirement{
				{
					Key:      "io.kubernetes.pod.namespace",
					Operator: "NotIn",
					Values:   []string{"foo"},
				},
				{
					Key:      "k8s:io.kubernetes.pod.namespace",
					Operator: "Exists",
				},
			}),
			ns: "bar",
		},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			out := tc.in.DeepCopy()
			EnsureNamespaceSelector(out, tc.ns)
			require.Equal(t, &tc.out, out)
		})
	}

}
