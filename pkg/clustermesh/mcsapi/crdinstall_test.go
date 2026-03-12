// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mcsapi

import (
	"testing"

	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	mcsapicrd "sigs.k8s.io/mcs-api/config/crd"
)

func newTestCRD(releaseVersion, revision string) *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				mcsapicrd.ReleaseVersionLabel:                         releaseVersion,
				mcsapicrd.CustomResourceDefinitionSchemaRevisionLabel: revision,
			},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Schema: &apiextensionsv1.CustomResourceValidation{},
			}},
		},
	}
}

func TestNeedsUpdateMCS(t *testing.T) {
	targetCRD := newTestCRD("v0.3.0", "42")

	tests := []struct {
		name       string
		currentCRD *apiextensionsv1.CustomResourceDefinition
		want       bool
	}{
		{
			name:       "updates when current release version is older",
			currentCRD: newTestCRD("v0.2.0", "99"),
			want:       true,
		},
		{
			name:       "does not update when current release version is newer",
			currentCRD: newTestCRD("v0.5.0", "0"),
			want:       false,
		},
		{
			name:       "updates when release version matches and revision is older",
			currentCRD: newTestCRD("v0.3.0", "0"),
			want:       true,
		},
		{
			name:       "does not update when release version matches and revision matches",
			currentCRD: newTestCRD("v0.3.0", "42"),
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := needsUpdateMCS(targetCRD, tt.currentCRD)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
