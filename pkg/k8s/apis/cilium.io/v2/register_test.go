// Copyright 2018 Authors of Cilium
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

package v2

import (
	"regexp"

	. "gopkg.in/check.v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CiliumV2RegisterSuite struct{}

var _ = Suite(&CiliumV2RegisterSuite{})

func (s *CiliumV2RegisterSuite) getTestUpToDateDefinition() *apiextensionsv1beta1.CustomResourceDefinition {
	return &apiextensionsv1beta1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				CustomResourceDefinitionSchemaVersionKey: CustomResourceDefinitionSchemaVersion,
			},
		},
		Spec: apiextensionsv1beta1.CustomResourceDefinitionSpec{
			Validation: &cnpCRV,
		},
	}
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateNoValidation(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Spec.Validation = nil

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

	crd.Labels[CustomResourceDefinitionSchemaVersionKey] = "0.9"

	c.Assert(needsUpdate(crd), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateCorruptedVersion(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Labels[CustomResourceDefinitionSchemaVersionKey] = "totally-not-semver"

	c.Assert(needsUpdate(crd), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestFQDNNameRegex(c *C) {
	nameRegex := regexp.MustCompile(fqdnNameRegex)
	patternRegex := regexp.MustCompile(fqdnPatternRegex)

	badFqdns := []string{
		"%%",
		"",
		"😀.com",
	}

	goodFqdns := []string{
		"cilium.io",
		"cilium.io.",
		"www.xn--e28h.com",
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
