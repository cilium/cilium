// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

func testEqualityRules(got, expected string, t *testing.T) {
	gotStruct := &PolicyUpdateNotification{}
	expectedStruct := &PolicyUpdateNotification{}

	err := json.Unmarshal([]byte(got), gotStruct)
	require.Nil(t, err)
	err = json.Unmarshal([]byte(expected), expectedStruct)
	require.Nil(t, err)
	require.EqualValues(t, expectedStruct, gotStruct)
}

func testEqualityEndpoint(got, expected string, t *testing.T) {
	gotStruct := &EndpointRegenNotification{}
	expectedStruct := &EndpointRegenNotification{}

	err := json.Unmarshal([]byte(got), gotStruct)
	require.Nil(t, err)
	err = json.Unmarshal([]byte(expected), expectedStruct)
	require.Nil(t, err)

	slices.Sort(gotStruct.Labels)
	slices.Sort(expectedStruct.Labels)
	require.EqualValues(t, expectedStruct, gotStruct)
}

func TestPolicyUpdateMessage(t *testing.T) {
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
	require.Nil(t, err)
	require.Equal(t, AgentNotifyPolicyUpdated, repr.Type)
	testEqualityRules(repr.Text, `{"labels":["unspec:key1=value1","unspec:key2=value2"],"revision":1,"rule_count":2}`, t)
}

func TestEmptyPolicyUpdateMessage(t *testing.T) {
	msg := PolicyUpdateMessage(0, []string{}, 1)
	repr, err := msg.ToJSON()
	require.Nil(t, err)
	require.Equal(t, AgentNotifyPolicyUpdated, repr.Type)
	testEqualityRules(repr.Text, `{"revision":1,"rule_count":0}`, t)
}

func TestPolicyDeleteMessage(t *testing.T) {
	lab := labels.LabelArray{
		labels.NewLabel("key1", "value1", labels.LabelSourceUnspec),
	}

	msg := PolicyDeleteMessage(1, lab.GetModel(), 2)
	repr, err := msg.ToJSON()
	require.Nil(t, err)
	require.Equal(t, AgentNotifyPolicyDeleted, repr.Type)
	testEqualityRules(repr.Text, `{"labels":["unspec:key1=value1"],"revision":2,"rule_count":1}`, t)
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

func TestEndpointRegenMessage(t *testing.T) {
	e := MockEndpoint{}
	rerr := RegenError{}

	msg := EndpointRegenMessage(e, rerr)
	repr, err := msg.ToJSON()
	require.Nil(t, err)
	require.Equal(t, AgentNotifyEndpointRegenerateFail, repr.Type)
	testEqualityEndpoint(repr.Text, `{"id":10,"labels":["unspec:key1=value1","unspec:key2=value2"],"error":"RegenError"}`, t)

	msg = EndpointRegenMessage(e, nil)
	repr, err = msg.ToJSON()
	require.Nil(t, err)
	require.Equal(t, AgentNotifyEndpointRegenerateSuccess, repr.Type)
	testEqualityEndpoint(repr.Text, `{"id":10,"labels":["unspec:key1=value1","unspec:key2=value2"]}`, t)
}

func TestStartMessage(t *testing.T) {
	now := time.Now()

	msg := StartMessage(now)
	repr, err := msg.ToJSON()
	require.Nil(t, err)
	require.Equal(t, AgentNotifyStart, repr.Type)

	var timeNotification TimeNotification
	json.Unmarshal([]byte(repr.Text), &timeNotification)
	parsedTS, err := time.Parse(time.RFC3339Nano, timeNotification.Time)
	require.Nil(t, err)
	// Truncate with duration <=0 will strip any monotonic clock reading
	require.Equal(t, true, parsedTS.Equal(now.Truncate(0)))
}
