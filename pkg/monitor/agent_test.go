// Copyright 2016-2018 Authors of Cilium
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

package monitor

import (
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type MonitorSuite struct{}

var _ = Suite(&MonitorSuite{})

func testEqualityRules(got, expected string, c *C) {
	gotStruct := &PolicyUpdateNotification{}
	expectedStruct := &PolicyUpdateNotification{}

	err := json.Unmarshal([]byte(got), gotStruct)
	c.Assert(err, IsNil)
	err = json.Unmarshal([]byte(expected), expectedStruct)
	c.Assert(err, IsNil)
	c.Assert(gotStruct, checker.DeepEquals, expectedStruct)
}

func testEqualityEndpoint(got, expected string, c *C) {
	gotStruct := &EndpointRegenNotification{}
	expectedStruct := &EndpointRegenNotification{}

	err := json.Unmarshal([]byte(got), gotStruct)
	c.Assert(err, IsNil)
	err = json.Unmarshal([]byte(expected), expectedStruct)
	c.Assert(err, IsNil)

	sort.Strings(gotStruct.Labels)
	sort.Strings(expectedStruct.Labels)
	c.Assert(gotStruct, checker.DeepEquals, expectedStruct)
}

func (s *MonitorSuite) TestRulesRepr(c *C) {
	rules := api.Rules{
		&api.Rule{
			Labels: labels.LabelArray{
				&labels.Label{
					Key:    "key1",
					Value:  "value1",
					Source: labels.LabelSourceUnspec,
				},
			},
		},
		&api.Rule{
			Labels: labels.LabelArray{
				&labels.Label{
					Key:    "key2",
					Value:  "value2",
					Source: labels.LabelSourceUnspec,
				},
			},
		},
	}

	repr, err := PolicyUpdateRepr(rules, 1)

	c.Assert(err, IsNil)
	testEqualityRules(repr, `{"labels":["unspec:key1=value1","unspec:key2=value2"],"revision":1,"rule_count":2}`, c)
}

func (s *MonitorSuite) TestRulesReprEmpty(c *C) {
	rules := api.Rules{}

	repr, err := PolicyUpdateRepr(rules, 1)

	c.Assert(err, IsNil)
	testEqualityRules(repr, `{"revision":1,"rule_count":0}`, c)
}

func (s *MonitorSuite) TestPolicyDeleteRepr(c *C) {
	lab := labels.LabelArray{
		&labels.Label{
			Key:    "key1",
			Value:  "value1",
			Source: labels.LabelSourceUnspec,
		},
	}

	repr, err := PolicyDeleteRepr(1, lab.GetModel(), 2)
	c.Assert(err, IsNil)
	testEqualityRules(repr, `{"labels":["unspec:key1=value1"],"revision":2,"rule_count":1}`, c)
}

type RegenError struct{}

func (RegenError) Error() string {
	return "RegenError"
}

type MockEndpoint struct{}

func (MockEndpoint) GetID() uint64 {
	return 10
}

func (MockEndpoint) GetOpLabels() []string {
	return labels.Labels{"label": &labels.Label{
		Key:    "key1",
		Value:  "value1",
		Source: labels.LabelSourceUnspec,
	},
		"label2": &labels.Label{
			Key:    "key2",
			Value:  "value2",
			Source: labels.LabelSourceUnspec,
		},
	}.GetModel()
}

func (s *MonitorSuite) TestEndpointRegenRepr(c *C) {
	e := MockEndpoint{}
	rerr := RegenError{}

	repr, err := EndpointRegenRepr(e, rerr)
	c.Assert(err, IsNil)
	testEqualityEndpoint(repr, `{"id":10,"labels":["unspec:key1=value1","unspec:key2=value2"],"error":"RegenError"}`, c)

	repr, err = EndpointRegenRepr(e, nil)
	c.Assert(err, IsNil)
	testEqualityEndpoint(repr, `{"id":10,"labels":["unspec:key1=value1","unspec:key2=value2"]}`, c)
}

func (s *MonitorSuite) TestTimeRepr(c *C) {
	t := time.Now()

	repr, err := TimeRepr(t)

	c.Assert(err, IsNil)
	c.Assert(repr, Equals, fmt.Sprintf(`{"time":"%s"}`, t.String()))
}
