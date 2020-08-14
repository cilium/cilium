// Copyright 2018-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package client

import (
	"regexp"
	"testing"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type CiliumV2RegisterSuite struct{}

var _ = Suite(&CiliumV2RegisterSuite{})

func (s *CiliumV2RegisterSuite) getTestUpToDateDefinition() *apiextensionsv1.CustomResourceDefinition {
	return &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				ciliumv2.CustomResourceDefinitionSchemaVersionKey: ciliumv2.CustomResourceDefinitionSchemaVersion,
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

func (s *CiliumV2RegisterSuite) TestNeedsUpdateNoValidation(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Spec.Versions[0].Schema = nil

	c.Assert(needsUpdate(crd), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateNoLabels(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Labels = nil

	c.Assert(needsUpdate(crd), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateNoVersionLabel(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Labels = map[string]string{"test": "test"}

	c.Assert(needsUpdate(crd), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateOlderVersion(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Labels[ciliumv2.CustomResourceDefinitionSchemaVersionKey] = "0.9"

	c.Assert(needsUpdate(crd), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateCorruptedVersion(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Labels[ciliumv2.CustomResourceDefinitionSchemaVersionKey] = "totally-not-semver"

	c.Assert(needsUpdate(crd), Equals, true)
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
