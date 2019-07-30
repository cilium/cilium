// Copyright 2018-2019 Authors of Cilium
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

package api

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/monitor/notifications"
)

// Must be synchronized with <bpf/lib/common.h>
const (
	// 0-128 are reserved for BPF datapath events
	MessageTypeUnspec = iota
	MessageTypeDrop
	MessageTypeDebug
	MessageTypeCapture
	MessageTypeTrace

	// 129-255 are reserved for agent level events

	// MessageTypeAccessLog contains a pkg/proxy/accesslog.LogRecord
	MessageTypeAccessLog = 129

	// MessageTypeAgent is an agent notification carrying a AgentNotify
	MessageTypeAgent = 130
)

type MessageTypeFilter []int

var (
	// MessageTypeNames is a map of all type names
	MessageTypeNames = map[string]int{
		"drop":    MessageTypeDrop,
		"debug":   MessageTypeDebug,
		"capture": MessageTypeCapture,
		"trace":   MessageTypeTrace,
		"l7":      MessageTypeAccessLog,
		"agent":   MessageTypeAgent,
	}
)

func type2name(typ int) string {
	for name, value := range MessageTypeNames {
		if value == typ {
			return name
		}
	}

	return strconv.Itoa(typ)
}

func (m *MessageTypeFilter) String() string {
	pieces := make([]string, 0, len(*m))
	for _, typ := range *m {
		pieces = append(pieces, type2name(typ))
	}

	return strings.Join(pieces, ",")
}

func (m *MessageTypeFilter) Set(value string) error {
	i, err := MessageTypeNames[value]
	if !err {
		return fmt.Errorf("Unknown type (%s). Please use one of the following ones %v",
			value, MessageTypeNames)
	}

	*m = append(*m, i)
	return nil
}

func (m *MessageTypeFilter) Type() string {
	return "[]string"
}

func (m *MessageTypeFilter) Contains(typ int) bool {
	for _, v := range *m {
		if v == typ {
			return true
		}
	}

	return false
}

// AgentNotify is a notification from the agent
type AgentNotify struct {
	Type AgentNotification
	Text string
}

// AgentNotification specifies the type of agent notification
type AgentNotification uint32

const (
	AgentNotifyUnspec AgentNotification = iota
	AgentNotifyGeneric
	AgentNotifyStart
	AgentNotifyEndpointRegenerateSuccess
	AgentNotifyEndpointRegenerateFail
	AgentNotifyPolicyUpdated
	AgentNotifyPolicyDeleted
	AgentNotifyEndpointCreated
	AgentNotifyEndpointDeleted
)

var notifyTable = map[AgentNotification]string{
	AgentNotifyUnspec:                    "unspecified",
	AgentNotifyGeneric:                   "Message",
	AgentNotifyStart:                     "Cilium agent started",
	AgentNotifyEndpointRegenerateSuccess: "Endpoint regenerated",
	AgentNotifyEndpointCreated:           "Endpoint created",
	AgentNotifyEndpointDeleted:           "Endpoint deleted",
	AgentNotifyEndpointRegenerateFail:    "Failed endpoint regeneration",
	AgentNotifyPolicyUpdated:             "Policy updated",
	AgentNotifyPolicyDeleted:             "Policy deleted",
}

func resolveAgentType(t AgentNotification) string {
	if n, ok := notifyTable[t]; ok {
		return n
	}

	return fmt.Sprintf("%d", t)
}

// DumpInfo dumps an agent notification
func (n *AgentNotify) DumpInfo() {
	fmt.Printf(">> %s: %s\n", resolveAgentType(n.Type), n.Text)
}

func (n *AgentNotify) getJSON() string {
	return fmt.Sprintf(`{"type":"agent","subtype":"%s","message":%s}`, resolveAgentType(n.Type), n.Text)
}

// DumpJSON prints notification in json format
func (n *AgentNotify) DumpJSON() {
	fmt.Println(n.getJSON())
}

// PolicyUpdateNotification structures update notification
type PolicyUpdateNotification struct {
	Labels    []string `json:"labels,omitempty"`
	Revision  uint64   `json:"revision,omitempty"`
	RuleCount int      `json:"rule_count"`
}

// PolicyUpdateRepr returns string representation of monitor notification
func PolicyUpdateRepr(numRules int, labels []string, revision uint64) (string, error) {
	notification := PolicyUpdateNotification{
		Labels:    labels,
		Revision:  revision,
		RuleCount: numRules,
	}

	repr, err := json.Marshal(notification)

	return string(repr), err
}

// PolicyDeleteRepr returns string representation of monitor notification
func PolicyDeleteRepr(deleted int, labels []string, revision uint64) (string, error) {
	notification := PolicyUpdateNotification{
		Labels:    labels,
		Revision:  revision,
		RuleCount: deleted,
	}
	repr, err := json.Marshal(notification)

	return string(repr), err
}

// EndpointRegenNotification structures regeneration notification
type EndpointRegenNotification struct {
	ID     uint64   `json:"id,omitempty"`
	Labels []string `json:"labels,omitempty"`
	Error  string   `json:"error,omitempty"`
}

// EndpointRegenRepr returns string representation of monitor notification
func EndpointRegenRepr(e notifications.RegenNotificationInfo, err error) (string, error) {
	notification := EndpointRegenNotification{
		ID:     e.GetID(),
		Labels: e.GetOpLabels(),
	}

	if err != nil {
		notification.Error = err.Error()
	}

	repr, err := json.Marshal(notification)

	return string(repr), err
}

// EndpointCreateNotification structures the endpoint create notification
type EndpointCreateNotification struct {
	EndpointRegenNotification
	PodName   string `json:"pod-name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// EndpointCreateRepr returns string representation of monitor notification
func EndpointCreateRepr(e notifications.RegenNotificationInfo) (string, error) {
	notification := EndpointCreateNotification{
		EndpointRegenNotification: EndpointRegenNotification{
			ID:     e.GetID(),
			Labels: e.GetOpLabels(),
		},
		PodName:   e.GetK8sPodName(),
		Namespace: e.GetK8sNamespace(),
	}

	repr, err := json.Marshal(notification)

	return string(repr), err
}

// EndpointDeleteNotification structures the an endpoint delete notification
type EndpointDeleteNotification struct {
	EndpointRegenNotification
	PodName   string `json:"pod-name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// EndpointDeleteRepr returns string representation of monitor notification
func EndpointDeleteRepr(e notifications.RegenNotificationInfo) (string, error) {
	notification := EndpointDeleteNotification{
		EndpointRegenNotification: EndpointRegenNotification{
			ID:     e.GetID(),
			Labels: e.GetOpLabels(),
		},
		PodName:   e.GetK8sPodName(),
		Namespace: e.GetK8sNamespace(),
	}

	repr, err := json.Marshal(notification)

	return string(repr), err
}

// TimeNotification structures agent start notification
type TimeNotification struct {
	Time string `json:"time"`
}

// TimeRepr returns string representation of monitor notification
func TimeRepr(t time.Time) (string, error) {
	notification := TimeNotification{
		Time: t.String(),
	}
	repr, err := json.Marshal(notification)
	return string(repr), err
}
