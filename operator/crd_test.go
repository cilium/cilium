// Copyright 2020 Authors of Cilium
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

package main

import (
	"context"
	"testing"

	k8sversion "github.com/cilium/cilium/pkg/k8s/version"

	. "gopkg.in/check.v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset/fake"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
)

var (
	v1CRD = &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "cilium.io",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Plural:     "foos",
				Singular:   "foo",
				ShortNames: []string{"foo"},
				Kind:       "Foo",
			},
			Scope: apiextensionsv1.ClusterScoped,
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

	v1beta1CRD = &apiextensionsv1beta1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "foo",
		},
		Spec: apiextensionsv1beta1.CustomResourceDefinitionSpec{
			Group: "cilium.io",
			Names: apiextensionsv1beta1.CustomResourceDefinitionNames{
				Plural:     "foos",
				Singular:   "foo",
				ShortNames: []string{"foo"},
				Kind:       "Foo",
			},
			Scope: apiextensionsv1beta1.ClusterScoped,
			Validation: &apiextensionsv1beta1.CustomResourceValidation{
				OpenAPIV3Schema: &apiextensionsv1beta1.JSONSchemaProps{},
			},
		},
	}
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type crdTestSuite struct{}

var _ = Suite(&crdTestSuite{})

func (s *crdTestSuite) TestGetCRD(c *C) {
	client := fake.NewSimpleClientset()

	v1Support := &version.Info{
		Major: "1",
		Minor: "16",
	}
	c.Assert(k8sversion.Force(v1Support.Major+"."+v1Support.Minor), IsNil)

	// v1 CRDs

	_, err := client.ApiextensionsV1().CustomResourceDefinitions().Create(
		context.TODO(),
		v1CRD,
		metav1.CreateOptions{},
	)
	c.Assert(err, IsNil)

	// Try to get existing CRD
	err = waitForCRD(context.TODO(), client, "foo")
	c.Assert(err, IsNil)

	// Try to get non-existing CRD
	err = waitForCRD(context.TODO(), client, "bar")
	c.Assert(err, ErrorMatches, ".*timeout waiting for CRD bar.*")

	// v1beta1 CRDs

	_, err = client.ApiextensionsV1beta1().CustomResourceDefinitions().Create(
		context.TODO(),
		v1beta1CRD,
		metav1.CreateOptions{},
	)
	c.Assert(err, IsNil)

	v1beta1Support := &version.Info{
		Major: "1",
		Minor: "15",
	}
	c.Assert(k8sversion.Force(v1beta1Support.Major+"."+v1beta1Support.Minor), IsNil)

	err = waitForCRD(context.TODO(), client, "foo")
	c.Assert(err, IsNil)

	err = waitForCRD(context.TODO(), client, "bar")
	c.Assert(err, ErrorMatches, ".*timeout waiting for CRD bar.*")
}
