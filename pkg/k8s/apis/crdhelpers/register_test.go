// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package crdhelpers

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"

	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/versioncheck"
)

func getV1TestCRD() *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo-v1",
			Labels: map[string]string{
				k8sconst.CustomResourceDefinitionSchemaVersionKey: k8sconst.CustomResourceDefinitionSchemaVersion,
			},
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{
					Name:    "v2",
					Served:  true,
					Storage: true,
					Schema: &apiextensionsv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{},
					},
				},
			},
		},
	}
}

func getV1beta1TestCRD() *apiextensionsv1beta1.CustomResourceDefinition {
	return &apiextensionsv1beta1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo-v1beta1",
			Labels: map[string]string{
				k8sconst.CustomResourceDefinitionSchemaVersionKey: k8sconst.CustomResourceDefinitionSchemaVersion,
			},
		},
		Spec: apiextensionsv1beta1.CustomResourceDefinitionSpec{
			Validation: &apiextensionsv1beta1.CustomResourceValidation{
				OpenAPIV3Schema: &apiextensionsv1beta1.JSONSchemaProps{},
			},
		},
	}
}

const labelKey = k8sconst.CustomResourceDefinitionSchemaVersionKey

var minVersion = versioncheck.MustVersion(k8sconst.CustomResourceDefinitionSchemaVersion)

func TestCreateUpdateCRD(t *testing.T) {
	v1Support := &version.Info{
		Major: "1",
		Minor: "16",
	}
	v1beta1Support := &version.Info{
		Major: "1",
		Minor: "15",
	}

	tests := []struct {
		name    string
		test    func() error
		wantErr bool
	}{
		{
			name: "v1 crd installed with v1 apiserver",
			test: func() error {
				crd := getV1TestCRD()
				client := fake.NewSimpleClientset()
				require.NoError(t, k8sversion.Force(v1Support.Major+"."+v1Support.Minor))
				return CreateUpdateCRD(hivetest.Logger(t), client, crd, newFakePoller(), labelKey, minVersion)
			},
			wantErr: false,
		},
		{
			name: "v1beta1 crd installed with v1beta1 apiserver",
			test: func() error {
				// createUpdateCRD works with v1 CRDs and converts to v1beta1 CRDs if needed.
				crd := getV1TestCRD()
				client := fake.NewSimpleClientset()
				require.NoError(t, k8sversion.Force(v1beta1Support.Major+"."+v1beta1Support.Minor))
				return CreateUpdateCRD(hivetest.Logger(t), client, crd, newFakePoller(), labelKey, minVersion)
			},
			wantErr: false,
		},
		{
			name: "v1beta1 crd installed with v1 apiserver; upgrade path",
			test: func() error {
				// This test will install a v1beta1 CRD to simulate the
				// scenario where a user already has v1beta1 CRDs installed.

				require.NoError(t, k8sversion.Force(v1Support.Major+"."+v1Support.Minor))

				// Ensure same name as to-be installed CRD.
				crd := getV1TestCRD()
				oldCRD := getV1beta1TestCRD()
				oldCRD.ObjectMeta.Name = crd.ObjectMeta.Name

				var err error
				client := fake.NewSimpleClientset()
				client.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = v1Support
				_, err = client.ApiextensionsV1beta1().CustomResourceDefinitions().Create(
					context.TODO(),
					oldCRD,
					metav1.CreateOptions{},
				)
				require.NoError(t, err)

				return CreateUpdateCRD(hivetest.Logger(t), client, crd, newFakePoller(), labelKey, minVersion)
			},
			wantErr: false,
		},
		{
			name: "v1 crd installed with v1beta1 apiserver; downgrade path",
			test: func() error {
				// This test will install a v1 CRD to simulate the scenario
				// where a user already has v1 CRDs installed. This test covers
				// that the apiserver will interoperate between the two
				// versions (v1 & v1beta1).

				require.NoError(t, k8sversion.Force(v1Support.Major+"."+v1Support.Minor))

				// Ensure same name as to-be installed CRD.
				crdToInstall := getV1beta1TestCRD()
				oldCRD := getV1TestCRD()
				oldCRD.ObjectMeta.Name = crdToInstall.ObjectMeta.Name

				// Pre-install v1 CRD.
				var err error
				client := fake.NewSimpleClientset()
				_, err = client.ApiextensionsV1().CustomResourceDefinitions().Create(
					context.TODO(),
					oldCRD,
					metav1.CreateOptions{},
				)
				require.NoError(t, err)

				// Revert back to v1beta1 apiserver.
				client.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = v1beta1Support
				require.NoError(t, k8sversion.Force(v1beta1Support.Major+"."+v1beta1Support.Minor))

				// Retrieve v1 CRD here as that's what CreateUpdateCRD will be
				// expecting, and change the name to match to-be installed CRD.
				// This tests that CreateUpdateCRD will fallback on its v1beta1
				// variant.
				crd := getV1TestCRD()
				crd.ObjectMeta.Name = crdToInstall.ObjectMeta.Name

				return CreateUpdateCRD(hivetest.Logger(t), client, crd, newFakePoller(), labelKey, minVersion)
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Log(tt.name)
		err := tt.test()
		require.Equal(t, tt.wantErr, err != nil)
	}
}

func TestNeedsUpdateNoValidation(t *testing.T) {
	v1CRD := getV1TestCRD()
	v1CRD.Spec.Versions[0].Schema = nil
	require.True(t, needsUpdateV1(v1CRD, labelKey, minVersion))
}

func TestNeedsUpdateNoLabels(t *testing.T) {
	v1CRD := getV1TestCRD()
	v1CRD.Labels = nil
	require.True(t, needsUpdateV1(v1CRD, labelKey, minVersion))
}

func TestNeedsUpdateNoVersionLabel(t *testing.T) {
	v1CRD := getV1TestCRD()
	v1CRD.Labels = map[string]string{"test": "test"}
	require.True(t, needsUpdateV1(v1CRD, labelKey, minVersion))
}

func TestNeedsUpdateOlderVersion(t *testing.T) {
	v1CRD := getV1TestCRD()
	v1CRD.Labels[k8sconst.CustomResourceDefinitionSchemaVersionKey] = "0.9"
	require.True(t, needsUpdateV1(v1CRD, labelKey, minVersion))
}

func TestNeedsUpdateCorruptedVersion(t *testing.T) {
	v1CRD := getV1TestCRD()
	v1CRD.Labels[k8sconst.CustomResourceDefinitionSchemaVersionKey] = "totally-not-semver"
	require.True(t, needsUpdateV1(v1CRD, labelKey, minVersion))
}

func TestFQDNNameRegex(t *testing.T) {
	nameRegex := regexp.MustCompile(api.FQDNMatchNameRegexString)
	patternRegex := regexp.MustCompile(api.FQDNMatchPatternRegexString)

	badFqdns := []string{
		"%%",
		"",
		"😀.com",
	}

	goodFqdns := []string{
		"cilium.io",
		"cilium.io.",
		"www.xn--e28h.com",
		"_tcp.cilium.io",
		"foo._tcp.cilium.io",
		"_http._tcp.cilium.io",
	}

	badFqdnPatterns := []string{
		"%$*.*",
		"",
	}

	goodFqdnPatterns := []string{
		"*.cilium.io",
		"*.cilium.io.*",
		"*.cilium.io.*.",
		"*.xn--e28h.com",
		"*._tcp.cilium.io",
		"*._tcp.*",
		"_http._tcp.*",
	}

	for _, f := range badFqdns {
		require.False(t, nameRegex.MatchString(f), f)
		require.False(t, patternRegex.MatchString(f), f)
	}

	for _, f := range goodFqdns {
		require.True(t, nameRegex.MatchString(f), f)
		require.True(t, patternRegex.MatchString(f), f)
	}

	for _, f := range badFqdnPatterns {
		require.False(t, nameRegex.MatchString(f), f)
		require.False(t, patternRegex.MatchString(f), f)
	}

	for _, f := range goodFqdnPatterns {
		require.False(t, nameRegex.MatchString(f), f)
		require.True(t, patternRegex.MatchString(f), f)
	}
}

func newFakePoller() fakePoller { return fakePoller{} }

type fakePoller struct{}

func (m fakePoller) Poll(
	interval, duration time.Duration,
	conditionFn func() (bool, error),
) error {
	return nil
}
