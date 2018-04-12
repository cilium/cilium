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

package utils

import (
	. "gopkg.in/check.v1"

	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CRDRegisterSuite struct{}

var _ = Suite(&CRDRegisterSuite{})

const (
	currentVersion = "1.5"
	nextVersion    = "1.6"
)

var (
	prop = apiextensionsv1beta1.JSONSchemaProps{
		Description: "I am a teapot",
		Type:        "string",
		OneOf: []apiextensionsv1beta1.JSONSchemaProps{
			{
				Type:    "string",
				Pattern: `abcd`,
			},
		},
	}

	dummyCRV = apiextensionsv1beta1.CustomResourceValidation{
		OpenAPIV3Schema: &apiextensionsv1beta1.JSONSchemaProps{
			Properties: map[string]apiextensionsv1beta1.JSONSchemaProps{
				"Field": prop,
			},
		},
	}
)

func (s *CRDRegisterSuite) getTestUpToDateDefinition() *apiextensionsv1beta1.CustomResourceDefinition {
	return &apiextensionsv1beta1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				CustomResourceDefinitionSchemaVersionKey: currentVersion,
			},
		},
		Spec: apiextensionsv1beta1.CustomResourceDefinitionSpec{
			Validation: &dummyCRV,
		},
	}
}

func (s *CRDRegisterSuite) TestNeedsUpdateNoValidation(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Spec.Validation = nil

	c.Assert(needsUpdate(crd, currentVersion), Equals, true)
	c.Assert(needsUpdate(crd, nextVersion), Equals, true)
}

func (s *CRDRegisterSuite) TestNeedsUpdateNoLabels(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Labels = nil

	c.Assert(needsUpdate(crd, currentVersion), Equals, true)
	c.Assert(needsUpdate(crd, nextVersion), Equals, true)
}

func (s *CRDRegisterSuite) TestNeedsUpdateNoVersionLabel(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Labels = map[string]string{"test": "test"}

	c.Assert(needsUpdate(crd, currentVersion), Equals, true)
	c.Assert(needsUpdate(crd, nextVersion), Equals, true)
}

func (s *CRDRegisterSuite) TestNeedsUpdateCorruptedVersion(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Labels[CustomResourceDefinitionSchemaVersionKey] = "totally-not-semver"

	c.Assert(needsUpdate(crd, currentVersion), Equals, true)
	c.Assert(needsUpdate(crd, nextVersion), Equals, true)
}

func (s *CRDRegisterSuite) TestNeedsUpdateOlderVersion(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Labels[CustomResourceDefinitionSchemaVersionKey] = currentVersion

	c.Assert(needsUpdate(crd, nextVersion), Equals, true)
}

func (s *CRDRegisterSuite) TestNoUpdateNewerVersion(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Labels[CustomResourceDefinitionSchemaVersionKey] = nextVersion

	c.Assert(needsUpdate(crd, currentVersion), Equals, true)
}

func (s *CRDRegisterSuite) TestNeedsUpdateValidationChange(c *C) {
	crd := s.getTestUpToDateDefinition()

	// based on dummyCRV
	crd.Spec.Validation.OpenAPIV3Schema.Properties = map[string]apiextensionsv1beta1.JSONSchemaProps{
		"Field": {
			Description: "not a teapot",
			Type:        "string",
			OneOf: []apiextensionsv1beta1.JSONSchemaProps{
				{
					Type:    "string",
					Pattern: `xyz`,
				},
			},
		},
	}

	c.Assert(needsUpdate(crd, nextVersion), Equals, true)
}
