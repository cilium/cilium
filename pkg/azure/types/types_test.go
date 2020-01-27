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

package types

import (
	"testing"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"gopkg.in/check.v1"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type TypesSuite struct{}

var _ = check.Suite(&TypesSuite{})

func (b *TypesSuite) TestInstanceMap(c *check.C) {
	m := InstanceMap{}
	c.Assert(m.Get("foo"), check.IsNil)
	m.Update("foo", &v2.AzureInterface{ID: "i-1"})
	c.Assert(len(m.Get("foo")), check.Equals, 1)
	m.Update("foo", &v2.AzureInterface{ID: "i-2"})
	c.Assert(len(m.Get("foo")), check.Equals, 2)
	m.Update("foo", &v2.AzureInterface{ID: "i-2"})
	c.Assert(len(m.Get("foo")), check.Equals, 2)
	m.Update("bar", &v2.AzureInterface{ID: "i-2"})
	c.Assert(len(m.Get("foo")), check.Equals, 2)
	c.Assert(len(m.Get("bar")), check.Equals, 1)
}
