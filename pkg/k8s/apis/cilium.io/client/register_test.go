// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client

import (
	"context"
	"regexp"
	"testing"
	"time"

	. "github.com/cilium/checkmate"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	fakediscovery "k8s.io/client-go/discovery/fake"

	k8sconst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/policy/api"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type CiliumV2RegisterSuite struct{}

var _ = Suite(&CiliumV2RegisterSuite{})

func (s *CiliumV2RegisterSuite) getV1TestCRD() *apiextensionsv1.CustomResourceDefinition {
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

func (s *CiliumV2RegisterSuite) getV1beta1TestCRD() *apiextensionsv1beta1.CustomResourceDefinition {
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

func (s *CiliumV2RegisterSuite) TestCreateUpdateCRD(c *C) {
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
				crd := s.getV1TestCRD()
				client := fake.NewSimpleClientset()
				c.Assert(k8sversion.Force(v1Support.Major+"."+v1Support.Minor), IsNil)
				return createUpdateCRD(client, crd, newFakePoller())
			},
			wantErr: false,
		},
		{
			name: "v1beta1 crd installed with v1beta1 apiserver",
			test: func() error {
				// createUpdateCRD works with v1 CRDs and converts to v1beta1 CRDs if needed.
				crd := s.getV1TestCRD()
				client := fake.NewSimpleClientset()
				c.Assert(k8sversion.Force(v1beta1Support.Major+"."+v1beta1Support.Minor), IsNil)
				return createUpdateCRD(client, crd, newFakePoller())
			},
			wantErr: false,
		},
		{
			name: "v1beta1 crd installed with v1 apiserver; upgrade path",
			test: func() error {
				// This test will install a v1beta1 CRD to simulate the
				// scenario where a user already has v1beta1 CRDs installed.

				c.Assert(k8sversion.Force(v1Support.Major+"."+v1Support.Minor), IsNil)

				// Ensure same name as to-be installed CRD.
				crd := s.getV1TestCRD()
				oldCRD := s.getV1beta1TestCRD()
				oldCRD.ObjectMeta.Name = crd.ObjectMeta.Name

				var err error
				client := fake.NewSimpleClientset()
				client.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = v1Support
				_, err = client.ApiextensionsV1beta1().CustomResourceDefinitions().Create(
					context.TODO(),
					oldCRD,
					v1.CreateOptions{},
				)
				c.Assert(err, IsNil)

				return createUpdateCRD(client, crd, newFakePoller())
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

				c.Assert(k8sversion.Force(v1Support.Major+"."+v1Support.Minor), IsNil)

				// Ensure same name as to-be installed CRD.
				crdToInstall := s.getV1beta1TestCRD()
				oldCRD := s.getV1TestCRD()
				oldCRD.ObjectMeta.Name = crdToInstall.ObjectMeta.Name

				// Pre-install v1 CRD.
				var err error
				client := fake.NewSimpleClientset()
				_, err = client.ApiextensionsV1().CustomResourceDefinitions().Create(
					context.TODO(),
					oldCRD,
					v1.CreateOptions{},
				)
				c.Assert(err, IsNil)

				// Revert back to v1beta1 apiserver.
				client.Discovery().(*fakediscovery.FakeDiscovery).FakedServerVersion = v1beta1Support
				c.Assert(k8sversion.Force(v1beta1Support.Major+"."+v1beta1Support.Minor), IsNil)

				// Retrieve v1 CRD here as that's what createUpdateCRD will be
				// expecting, and change the name to match to-be installed CRD.
				// This tests that createUpdateCRD will fallback on its v1beta1
				// variant.
				crd := s.getV1TestCRD()
				crd.ObjectMeta.Name = crdToInstall.ObjectMeta.Name

				return createUpdateCRD(client, crd, newFakePoller())
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		c.Log(tt.name)
		err := tt.test()
		c.Assert((err != nil), Equals, tt.wantErr)
	}
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateNoValidation(c *C) {
	v1CRD := s.getV1TestCRD()
	v1CRD.Spec.Versions[0].Schema = nil
	c.Assert(needsUpdateV1(v1CRD), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateNoLabels(c *C) {
	v1CRD := s.getV1TestCRD()
	v1CRD.Labels = nil
	c.Assert(needsUpdateV1(v1CRD), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateNoVersionLabel(c *C) {
	v1CRD := s.getV1TestCRD()
	v1CRD.Labels = map[string]string{"test": "test"}
	c.Assert(needsUpdateV1(v1CRD), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateOlderVersion(c *C) {
	v1CRD := s.getV1TestCRD()
	v1CRD.Labels[k8sconst.CustomResourceDefinitionSchemaVersionKey] = "0.9"
	c.Assert(needsUpdateV1(v1CRD), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateCorruptedVersion(c *C) {
	v1CRD := s.getV1TestCRD()
	v1CRD.Labels[k8sconst.CustomResourceDefinitionSchemaVersionKey] = "totally-not-semver"
	c.Assert(needsUpdateV1(v1CRD), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestFQDNNameRegex(c *C) {
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
		c.Assert(nameRegex.MatchString(f), Equals, false, Commentf(f))
		c.Assert(patternRegex.MatchString(f), Equals, false, Commentf(f))
	}

	for _, f := range goodFqdns {
		c.Assert(nameRegex.MatchString(f), Equals, true, Commentf(f))
		c.Assert(patternRegex.MatchString(f), Equals, true, Commentf(f))
	}

	for _, f := range badFqdnPatterns {
		c.Assert(nameRegex.MatchString(f), Equals, false, Commentf(f))
		c.Assert(patternRegex.MatchString(f), Equals, false, Commentf(f))
	}

	for _, f := range goodFqdnPatterns {
		c.Assert(nameRegex.MatchString(f), Equals, false, Commentf(f))
		c.Assert(patternRegex.MatchString(f), Equals, true, Commentf(f))
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
