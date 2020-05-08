// Copyright 2019 Authors of Cilium
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

package identitybackend

import (
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1/validation"

	. "gopkg.in/check.v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type K8sIdentityBackendSuite struct{}

var _ = Suite(&K8sIdentityBackendSuite{})

func (s *K8sIdentityBackendSuite) TestSanitizeK8sLabels(c *C) {
	path := field.NewPath("test", "labels")
	testCases := []struct {
		input            map[string]string
		selected         map[string]string
		skipped          map[string]string
		validationErrors field.ErrorList
	}{
		{
			input:            map[string]string{},
			selected:         map[string]string{},
			skipped:          map[string]string{},
			validationErrors: field.ErrorList{},
		},
		{
			input:            map[string]string{"k8s:foo": "bar"},
			selected:         map[string]string{"foo": "bar"},
			skipped:          map[string]string{},
			validationErrors: field.ErrorList{},
		},
		{
			input:            map[string]string{"k8s:foo": "bar", "k8s:abc": "def"},
			selected:         map[string]string{"foo": "bar", "abc": "def"},
			skipped:          map[string]string{},
			validationErrors: field.ErrorList{},
		},
		{
			input:            map[string]string{"k8s:foo": "bar", "k8s:abc": "def", "container:something": "else"},
			selected:         map[string]string{"foo": "bar", "abc": "def"},
			skipped:          map[string]string{"container:something": "else"},
			validationErrors: field.ErrorList{},
		},
		{
			input:    map[string]string{"k8s:some.really.really.really.really.really.really.really.long.label.name": "someval"},
			selected: map[string]string{"some.really.really.really.really.really.really.really.long.label.name": "someval"},
			skipped:  map[string]string{},
			validationErrors: field.ErrorList{
				&field.Error{
					Type:     "FieldValueInvalid",
					Field:    "test.labels",
					BadValue: "some.really.really.really.really.really.really.really.long.label.name",
					Detail:   "name part must be no more than 63 characters",
				},
			},
		},
		{
			input:            map[string]string{"k8s:io.cilium.k8s.namespace.labels.some.really.really.long.namespace.label.name": "someval"},
			selected:         map[string]string{},
			skipped:          map[string]string{"k8s:io.cilium.k8s.namespace.labels.some.really.really.long.namespace.label.name": "someval"},
			validationErrors: field.ErrorList{},
		},
	}

	for _, test := range testCases {
		selected, skipped := sanitizeK8sLabels(test.input)
		c.Assert(selected, checker.DeepEquals, test.selected)
		c.Assert(skipped, checker.DeepEquals, test.skipped)
		c.Assert(validation.ValidateLabels(selected, path), checker.DeepEquals, test.validationErrors)
	}
}
