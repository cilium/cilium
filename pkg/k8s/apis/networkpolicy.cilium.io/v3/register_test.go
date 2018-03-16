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

package v3

import (
	. "gopkg.in/check.v1"

	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type CiliumV3RegisterSuite struct{}

var _ = Suite(&CiliumV3RegisterSuite{})

func (s *CiliumV3RegisterSuite) getTestUpToDateDefinition() *apiextensionsv1beta1.CustomResourceDefinition {
	return &apiextensionsv1beta1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{
				CustomResourceDefinitionSchemaVersionKey: CustomResourceDefinitionSchemaVersion,
			},
		},
		Spec: apiextensionsv1beta1.CustomResourceDefinitionSpec{
			Validation: cnpCRV,
		},
	}
}

func (s *CiliumV3RegisterSuite) TestNeedsUpdateNoValidation(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Spec.Validation = nil

	c.Assert(needsUpdate(crd), Equals, true)
}

func (s *CiliumV3RegisterSuite) TestNeedsUpdateNoLabels(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Labels = nil

	c.Assert(needsUpdate(crd), Equals, true)
}

func (s *CiliumV3RegisterSuite) TestNeedsUpdateNoVersionLabel(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Labels = map[string]string{"test": "test"}

	c.Assert(needsUpdate(crd), Equals, true)
}

func (s *CiliumV3RegisterSuite) TestNeedsUpdateOlderVersion(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Labels[CustomResourceDefinitionSchemaVersionKey] = "0.9"

	c.Assert(needsUpdate(crd), Equals, true)
}

func (s *CiliumV3RegisterSuite) TestNeedsUpdateCorruptedVersion(c *C) {
	crd := s.getTestUpToDateDefinition()

	crd.Labels[CustomResourceDefinitionSchemaVersionKey] = "totally-not-semver"

	c.Assert(needsUpdate(crd), Equals, true)
}
