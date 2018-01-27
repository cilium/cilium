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

package v2

import (
	. "gopkg.in/check.v1"

	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
			Validation: &crv,
		},
	}
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateNoUpdate(c *C) {
	crd := s.getTestUpToDateDefinition()
	e := errors.NewAlreadyExists(schema.GroupResource{}, "")

	c.Assert(needsUpdate(crd, e), Equals, false)
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateNoValidation(c *C) {
	crd := s.getTestUpToDateDefinition()
	e := errors.NewAlreadyExists(schema.GroupResource{}, "")

	crd.Spec.Validation = nil

	c.Assert(needsUpdate(crd, e), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateNoLabels(c *C) {
	crd := s.getTestUpToDateDefinition()
	e := errors.NewAlreadyExists(schema.GroupResource{}, "")

	crd.Labels = nil

	c.Assert(needsUpdate(crd, e), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateNoVersionLabel(c *C) {
	crd := s.getTestUpToDateDefinition()
	e := errors.NewAlreadyExists(schema.GroupResource{}, "")

	crd.Labels = map[string]string{"test": "test"}

	c.Assert(needsUpdate(crd, e), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateOlderVersion(c *C) {
	crd := s.getTestUpToDateDefinition()
	e := errors.NewAlreadyExists(schema.GroupResource{}, "")

	crd.Labels[CustomResourceDefinitionSchemaVersionKey] = "0.9"

	c.Assert(needsUpdate(crd, e), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateCorruptedVersion(c *C) {
	crd := s.getTestUpToDateDefinition()
	e := errors.NewAlreadyExists(schema.GroupResource{}, "")

	crd.Labels[CustomResourceDefinitionSchemaVersionKey] = "totally-not-semver"

	c.Assert(needsUpdate(crd, e), Equals, true)
}

func (s *CiliumV2RegisterSuite) TestNeedsUpdateWrongError(c *C) {
	crd := s.getTestUpToDateDefinition()
	e := errors.NewUnauthorized("")

	// Should be false, but this code path is unavailable in normal use.
	// All errors other than AlreadyExists are handled before calling needsUpdate
	c.Assert(needsUpdate(crd, e), Equals, false)
}
