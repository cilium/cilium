// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/json"
	"sort"
	"testing"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type MonitorAPISuite struct{}

var _ = Suite(&MonitorAPISuite{})

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

func (s *MonitorAPISuite) TestPolicyUpdateMessage(c *C) {
	rules := api.Rules{
		&api.Rule{
			Labels: labels.LabelArray{
				labels.NewLabel("key1", "value1", labels.LabelSourceUnspec),
			},
		},
		&api.Rule{
			Labels: labels.LabelArray{
				labels.NewLabel("key2", "value2", labels.LabelSourceUnspec),
			},
		},
	}

	labels := make([]string, 0, len(rules))
	for _, r := range rules {
		labels = append(labels, r.Labels.GetModel()...)
	}

	msg := PolicyUpdateMessage(len(rules), labels, 1)
	repr, err := msg.ToJSON()
	c.Assert(err, IsNil)
	c.Assert(repr.Type, Equals, AgentNotifyPolicyUpdated)
	testEqualityRules(repr.Text, `{"labels":["unspec:key1=value1","unspec:key2=value2"],"revision":1,"rule_count":2}`, c)
}

func (s *MonitorAPISuite) TestEmptyPolicyUpdateMessage(c *C) {
	msg := PolicyUpdateMessage(0, []string{}, 1)
	repr, err := msg.ToJSON()
	c.Assert(err, IsNil)
	c.Assert(repr.Type, Equals, AgentNotifyPolicyUpdated)
	testEqualityRules(repr.Text, `{"revision":1,"rule_count":0}`, c)
}

func (s *MonitorAPISuite) TestPolicyDeleteMessage(c *C) {
	lab := labels.LabelArray{
		labels.NewLabel("key1", "value1", labels.LabelSourceUnspec),
	}

	msg := PolicyDeleteMessage(1, lab.GetModel(), 2)
	repr, err := msg.ToJSON()
	c.Assert(err, IsNil)
	c.Assert(repr.Type, Equals, AgentNotifyPolicyDeleted)
	testEqualityRules(repr.Text, `{"labels":["unspec:key1=value1"],"revision":2,"rule_count":1}`, c)
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
	return labels.Labels{"label": labels.NewLabel("key1", "value1", labels.LabelSourceUnspec),
		"label2": labels.NewLabel("key2", "value2", labels.LabelSourceUnspec),
	}.GetModel()
}

func (MockEndpoint) GetK8sPodName() string {
	return ""
}

func (MockEndpoint) GetK8sNamespace() string {
	return ""
}

func (MockEndpoint) GetID16() uint16 {
	return 0
}

func (s *MonitorAPISuite) TestEndpointRegenMessage(c *C) {
	e := MockEndpoint{}
	rerr := RegenError{}

	msg := EndpointRegenMessage(e, rerr)
	repr, err := msg.ToJSON()
	c.Assert(err, IsNil)
	c.Assert(repr.Type, Equals, AgentNotifyEndpointRegenerateFail)
	testEqualityEndpoint(repr.Text, `{"id":10,"labels":["unspec:key1=value1","unspec:key2=value2"],"error":"RegenError"}`, c)

	msg = EndpointRegenMessage(e, nil)
	repr, err = msg.ToJSON()
	c.Assert(err, IsNil)
	c.Assert(repr.Type, Equals, AgentNotifyEndpointRegenerateSuccess)
	testEqualityEndpoint(repr.Text, `{"id":10,"labels":["unspec:key1=value1","unspec:key2=value2"]}`, c)
}

func (s *MonitorAPISuite) TestStartMessage(c *C) {
	t := time.Now()

	msg := StartMessage(t)
	repr, err := msg.ToJSON()
	c.Assert(err, IsNil)
	c.Assert(repr.Type, Equals, AgentNotifyStart)

	var timeNotification TimeNotification
	json.Unmarshal([]byte(repr.Text), &timeNotification)
	parsedTS, err := time.Parse(time.RFC3339Nano, timeNotification.Time)
	c.Assert(err, IsNil)
	// Truncate with duration <=0 will strip any monotonic clock reading
	c.Assert(parsedTS.Equal(t.Truncate(0)), Equals, true)
}
