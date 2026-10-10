// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package apis

import (
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sTestutils "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/option"
)

func newTestKCNPCRD(bundleVersion, channel string) *apiextensionsv1.CustomResourceDefinition {
	annotations := map[string]string{}
	if bundleVersion != "" {
		annotations[kcnpBundleVersionAnnotation] = bundleVersion
	}
	if channel != "" {
		annotations[kcnpChannelAnnotation] = channel
	}
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name:        synced.KCNPCRDName,
			Annotations: annotations,
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{{
				Schema: &apiextensionsv1.CustomResourceValidation{},
			}},
		},
	}
}

func TestKCNPBundleVersion(t *testing.T) {
	version, err := kcnpBundleVersion(newTestKCNPCRD("v0.2.0", ""))
	require.NoError(t, err)
	require.Equal(t, "0.2.0", version.String())

	_, err = kcnpBundleVersion(newTestKCNPCRD("", ""))
	require.ErrorContains(t, err, "missing")

	_, err = kcnpBundleVersion(newTestKCNPCRD("not-a-semver", ""))
	require.ErrorContains(t, err, "invalid")
}

func TestNeedsUpdateKCNP(t *testing.T) {
	needsUpdateKCNP := newNeedsUpdateKCNPFunc(hivetest.Logger(t))
	targetCRD := newTestKCNPCRD("v0.2.0", "standard")

	tests := []struct {
		name       string
		currentCRD *apiextensionsv1.CustomResourceDefinition
		want       bool
	}{
		{
			name:       "updates when current bundle version is older",
			currentCRD: newTestKCNPCRD("v0.1.7", "standard"),
			want:       true,
		},
		{
			name:       "does not update when current bundle version matches",
			currentCRD: newTestKCNPCRD("v0.2.0", "standard"),
			want:       false,
		},
		{
			name:       "does not update when current bundle version is newer",
			currentCRD: newTestKCNPCRD("v0.3.0", "standard"),
			want:       false,
		},
		{
			name:       "updates when current bundle version annotation is missing",
			currentCRD: newTestKCNPCRD("", "standard"),
			want:       true,
		},
		{
			name:       "updates when current bundle version annotation is invalid",
			currentCRD: newTestKCNPCRD("not-a-semver", "standard"),
			want:       true,
		},
		{
			name:       "updates when current channel annotation is missing",
			currentCRD: newTestKCNPCRD("v0.1.7", ""),
			want:       true,
		},
		{
			name:       "does not update when current channel differs and version is older",
			currentCRD: newTestKCNPCRD("v0.1.7", "experimental"),
			want:       false,
		},
		{
			name:       "does not update when current channel differs and version matches",
			currentCRD: newTestKCNPCRD("v0.2.0", "experimental"),
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := needsUpdateKCNP(targetCRD, tt.currentCRD)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}

	t.Run("fails when target bundle version annotation is missing", func(t *testing.T) {
		_, err := needsUpdateKCNP(newTestKCNPCRD("", "standard"), newTestKCNPCRD("v0.1.7", "standard"))
		require.Error(t, err)
	})
}

// newOutdatedKCNPCRD returns the pregenerated CRD with an older bundle
// version, i.e. a CRD which needs to be updated.
func newOutdatedKCNPCRD(t *testing.T) *apiextensionsv1.CustomResourceDefinition {
	target, err := getPregeneratedKCNPCRD()
	require.NoError(t, err)
	require.Equal(t, synced.KCNPCRDName, target.Name)
	require.Equal(t, "v0.2.0", target.Annotations[kcnpBundleVersionAnnotation])
	require.Equal(t, "standard", target.Annotations[kcnpChannelAnnotation])

	outdated := target.DeepCopy()
	outdated.Annotations[kcnpBundleVersionAnnotation] = "v0.1.7"
	outdated.Status.Conditions = []apiextensionsv1.CustomResourceDefinitionCondition{{
		Type:   apiextensionsv1.Established,
		Status: apiextensionsv1.ConditionTrue,
	}}
	return outdated
}

func TestCreateKCNPCRD(t *testing.T) {
	logger := hivetest.Logger(t)
	client := fake.NewSimpleClientset(newOutdatedKCNPCRD(t))

	_, err := createKCNPCRD(t.Context(), logger, client)
	require.NoError(t, err)

	updated, err := client.ApiextensionsV1().CustomResourceDefinitions().Get(t.Context(), synced.KCNPCRDName, metav1.GetOptions{})
	require.NoError(t, err)
	require.Equal(t, "v0.2.0", updated.Annotations[kcnpBundleVersionAnnotation])
}

func TestNewKCNPCRDs(t *testing.T) {
	tests := []struct {
		name        string
		enabled     bool
		installCRDs bool
		wantVersion string
	}{
		{
			name:        "installs the CRD when enabled",
			enabled:     true,
			installCRDs: true,
			wantVersion: "v0.2.0",
		},
		{
			name:        "does not touch the CRD when installation is disabled",
			enabled:     true,
			installCRDs: false,
			wantVersion: "v0.1.7",
		},
		{
			name:        "does not touch the CRD when K8s ClusterNetworkPolicy is disabled",
			enabled:     false,
			installCRDs: true,
			wantVersion: "v0.1.7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			_, clientset := k8sTestutils.NewFakeClientset(logger)
			_, err := clientset.ApiextensionsV1().CustomResourceDefinitions().Create(t.Context(), newOutdatedKCNPCRD(t), metav1.CreateOptions{})
			require.NoError(t, err)

			registerCRDs := newKCNPCRDs(kcnpCRDParams{
				DaemonConfig: &option.DaemonConfig{EnableK8sClusterNetworkPolicy: tt.enabled},
				Config:       kcnpCRDConfig{K8sClusterNetworkPolicyInstallCRDs: tt.installCRDs},
			}).Func
			_, err = registerCRDs(t.Context(), logger, clientset)
			require.NoError(t, err)

			crd, err := clientset.ApiextensionsV1().CustomResourceDefinitions().Get(t.Context(), synced.KCNPCRDName, metav1.GetOptions{})
			require.NoError(t, err)
			require.Equal(t, tt.wantVersion, crd.Annotations[kcnpBundleVersionAnnotation])
		})
	}

	t.Run("does not fail when installation is disabled and the CRD is missing", func(t *testing.T) {
		logger := hivetest.Logger(t)
		_, clientset := k8sTestutils.NewFakeClientset(logger)

		registerCRDs := newKCNPCRDs(kcnpCRDParams{
			DaemonConfig: &option.DaemonConfig{EnableK8sClusterNetworkPolicy: true},
			Config:       kcnpCRDConfig{K8sClusterNetworkPolicyInstallCRDs: false},
		}).Func
		_, err := registerCRDs(t.Context(), logger, clientset)
		require.NoError(t, err)
		require.Error(t, k8sClient.CheckCRD(t.Context(), clientset, kcnpGVK))
	})
}
