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
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/monitor/notifications"
)

// Must be synchronized with <bpf/lib/common.h>
const (
	// 0-128 are reserved for BPF datapath events
	MessageTypeUnspec = iota

	// MessageTypeDrop is a BPF datapath notification carrying a DropNotify
	// which corresponds to drop_notify defined in bpf/lib/drop.h
	MessageTypeDrop

	// MessageTypeDebug is a BPF datapath notification carrying a DebugMsg
	// which corresponds to debug_msg defined in bpf/lib/dbg.h
	MessageTypeDebug

	// MessageTypeCapture is a BPF datapath notification carrying a DebugCapture
	// which corresponds to debug_capture_msg defined in bpf/lib/dbg.h
	MessageTypeCapture

	// MessageTypeTrace is a BPF datapath notification carrying a TraceNotify
	// which corresponds to trace_notify defined in bpf/lib/trace.h
	MessageTypeTrace

	// MessageTypePolicyVerdict is a BPF datapath notification carrying a PolicyVerdictNotify
	// which corresponds to policy_verdict_notify defined in bpf/lib/policy_log.h
	MessageTypePolicyVerdict

	// 129-255 are reserved for agent level events

	// MessageTypeAccessLog contains a pkg/proxy/accesslog.LogRecord
	MessageTypeAccessLog = 129

	// MessageTypeAgent is an agent notification carrying a AgentNotify
	MessageTypeAgent = 130
)

const (
	MessageTypeNameDrop          = "drop"
	MessageTypeNameDebug         = "debug"
	MessageTypeNameCapture       = "capture"
	MessageTypeNameTrace         = "trace"
	MessageTypeNameL7            = "l7"
	MessageTypeNameAgent         = "agent"
	MessageTypeNamePolicyVerdict = "policy-verdict"
)

type MessageTypeFilter []int

var (
	// MessageTypeNames is a map of all type names
	MessageTypeNames = map[string]int{
		MessageTypeNameDrop:          MessageTypeDrop,
		MessageTypeNameDebug:         MessageTypeDebug,
		MessageTypeNameCapture:       MessageTypeCapture,
		MessageTypeNameTrace:         MessageTypeTrace,
		MessageTypeNameL7:            MessageTypeAccessLog,
		MessageTypeNameAgent:         MessageTypeAgent,
		MessageTypeNamePolicyVerdict: MessageTypePolicyVerdict,
	}
)

// MessageTypeName returns the name for a message type or the numeric value if
// the name can't be found
func MessageTypeName(typ int) string {
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
		pieces = append(pieces, MessageTypeName(typ))
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

// Must be synchronized with <bpf/lib/trace.h>
const (
	TraceToLxc = iota
	TraceToProxy
	TraceToHost
	TraceToStack
	TraceToOverlay
	TraceFromLxc
	TraceFromProxy
	TraceFromHost
	TraceFromStack
	TraceFromOverlay
	TraceFromNetwork
	TraceToNetwork
)

// TraceObservationPoints is a map of all supported trace observation points
var TraceObservationPoints = map[uint8]string{
	TraceToLxc:       "to-endpoint",
	TraceToProxy:     "to-proxy",
	TraceToHost:      "to-host",
	TraceToStack:     "to-stack",
	TraceToOverlay:   "to-overlay",
	TraceToNetwork:   "to-network",
	TraceFromLxc:     "from-endpoint",
	TraceFromProxy:   "from-proxy",
	TraceFromHost:    "from-host",
	TraceFromStack:   "from-stack",
	TraceFromOverlay: "from-overlay",
	TraceFromNetwork: "from-network",
}

// TraceObservationPoint returns the name of a trace observation point
func TraceObservationPoint(obsPoint uint8) string {
	if str, ok := TraceObservationPoints[obsPoint]; ok {
		return str
	}
	return fmt.Sprintf("%d", obsPoint)
}

// TraceObservationPointHasConnState returns true if the observation point
// obsPoint populates the TraceNotify.Reason field with connection tracking
// information.
func TraceObservationPointHasConnState(obsPoint uint8) bool {
	switch obsPoint {
	case TraceToLxc,
		TraceToProxy,
		TraceToHost,
		TraceToStack,
		TraceToNetwork:
		return true
	default:
		return false
	}
}

// AgentNotify is a notification from the agent. The notification is stored
// in its JSON-encoded representation
type AgentNotify struct {
	Type AgentNotification
	Text string
}

// AgentNotify is a notification from the agent. It is similar to AgentNotify,
// but the notification is an unencoded struct. See the *Message constructors
// in this package for possible values.
type AgentNotifyMessage struct {
	Type         AgentNotification
	Notification interface{}
}

// ToJSON encodes a AgentNotifyMessage to its JSON-based AgentNotify representation
func (m *AgentNotifyMessage) ToJSON() (AgentNotify, error) {
	repr, err := json.Marshal(m.Notification)
	if err != nil {
		return AgentNotify{}, err
	}
	return AgentNotify{
		Type: m.Type,
		Text: string(repr),
	}, nil
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
	AgentNotifyIPCacheUpserted
	AgentNotifyIPCacheDeleted
	AgentNotifyServiceUpserted
	AgentNotifyServiceDeleted
)

var notifyTable = map[AgentNotification]string{
	AgentNotifyUnspec:                    "unspecified",
	AgentNotifyGeneric:                   "Message",
	AgentNotifyStart:                     "Cilium agent started",
	AgentNotifyEndpointRegenerateSuccess: "Endpoint regenerated",
	AgentNotifyEndpointCreated:           "Endpoint created",
	AgentNotifyEndpointDeleted:           "Endpoint deleted",
	AgentNotifyEndpointRegenerateFail:    "Failed endpoint regeneration",
	AgentNotifyIPCacheDeleted:            "IPCache entry deleted",
	AgentNotifyIPCacheUpserted:           "IPCache entry upserted",
	AgentNotifyPolicyUpdated:             "Policy updated",
	AgentNotifyPolicyDeleted:             "Policy deleted",
	AgentNotifyServiceDeleted:            "Service deleted",
	AgentNotifyServiceUpserted:           "Service upserted",
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

// PolicyUpdateMessage constructs an agent notification message for policy updates
func PolicyUpdateMessage(numRules int, labels []string, revision uint64) AgentNotifyMessage {
	notification := PolicyUpdateNotification{
		Labels:    labels,
		Revision:  revision,
		RuleCount: numRules,
	}

	return AgentNotifyMessage{
		Type:         AgentNotifyPolicyUpdated,
		Notification: notification,
	}
}

// PolicyDeleteMessage constructs an agent notification message for policy deletion
func PolicyDeleteMessage(deleted int, labels []string, revision uint64) AgentNotifyMessage {
	notification := PolicyUpdateNotification{
		Labels:    labels,
		Revision:  revision,
		RuleCount: deleted,
	}

	return AgentNotifyMessage{
		Type:         AgentNotifyPolicyDeleted,
		Notification: notification,
	}
}

// EndpointRegenNotification structures regeneration notification
type EndpointRegenNotification struct {
	ID     uint64   `json:"id,omitempty"`
	Labels []string `json:"labels,omitempty"`
	Error  string   `json:"error,omitempty"`
}

// EndpointRegenMessage constructs an agent notification message for endpoint regeneration
func EndpointRegenMessage(e notifications.RegenNotificationInfo, err error) AgentNotifyMessage {
	notification := EndpointRegenNotification{
		ID:     e.GetID(),
		Labels: e.GetOpLabels(),
	}

	typ := AgentNotifyEndpointRegenerateSuccess
	if err != nil {
		notification.Error = err.Error()
		typ = AgentNotifyEndpointRegenerateFail
	}

	return AgentNotifyMessage{
		Type:         typ,
		Notification: notification,
	}
}

// EndpointCreateNotification structures the endpoint create notification
type EndpointCreateNotification struct {
	EndpointRegenNotification
	PodName   string `json:"pod-name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// EndpointCreateMessage constructs an agent notification message for endpoint creation
func EndpointCreateMessage(e notifications.RegenNotificationInfo) AgentNotifyMessage {
	notification := EndpointCreateNotification{
		EndpointRegenNotification: EndpointRegenNotification{
			ID:     e.GetID(),
			Labels: e.GetOpLabels(),
		},
		PodName:   e.GetK8sPodName(),
		Namespace: e.GetK8sNamespace(),
	}

	return AgentNotifyMessage{
		Type:         AgentNotifyEndpointCreated,
		Notification: notification,
	}
}

// EndpointDeleteNotification structures the an endpoint delete notification
type EndpointDeleteNotification struct {
	EndpointRegenNotification
	PodName   string `json:"pod-name,omitempty"`
	Namespace string `json:"namespace,omitempty"`
}

// EndpointDeleteMessage constructs an agent notification message for endpoint deletion
func EndpointDeleteMessage(e notifications.RegenNotificationInfo) AgentNotifyMessage {
	notification := EndpointDeleteNotification{
		EndpointRegenNotification: EndpointRegenNotification{
			ID:     e.GetID(),
			Labels: e.GetOpLabels(),
		},
		PodName:   e.GetK8sPodName(),
		Namespace: e.GetK8sNamespace(),
	}

	return AgentNotifyMessage{
		Type:         AgentNotifyEndpointDeleted,
		Notification: notification,
	}
}

// IPCacheNotification structures ipcache change notifications
type IPCacheNotification struct {
	CIDR        string  `json:"cidr"`
	Identity    uint32  `json:"id"`
	OldIdentity *uint32 `json:"old-id,omitempty"`

	HostIP    net.IP `json:"host-ip,omitempty"`
	OldHostIP net.IP `json:"old-host-ip,omitempty"`

	EncryptKey uint8  `json:"encrypt-key"`
	Namespace  string `json:"namespace,omitempty"`
	PodName    string `json:"pod-name,omitempty"`
}

// IPCacheUpsertedMessage constructs an agent notification message for ipcache upsertions
func IPCacheUpsertedMessage(cidr string, id uint32, oldID *uint32, hostIP net.IP, oldHostIP net.IP,
	encryptKey uint8, namespace, podName string) AgentNotifyMessage {
	notification := IPCacheNotification{
		CIDR:        cidr,
		Identity:    id,
		OldIdentity: oldID,
		HostIP:      hostIP,
		OldHostIP:   oldHostIP,
		EncryptKey:  encryptKey,
		Namespace:   namespace,
		PodName:     podName,
	}

	return AgentNotifyMessage{
		Type:         AgentNotifyIPCacheUpserted,
		Notification: notification,
	}
}

// IPCacheDeletedMessage constructs an agent notification message for ipcache deletions
func IPCacheDeletedMessage(cidr string, id uint32, oldID *uint32, hostIP net.IP, oldHostIP net.IP,
	encryptKey uint8, namespace, podName string) AgentNotifyMessage {
	notification := IPCacheNotification{
		CIDR:        cidr,
		Identity:    id,
		OldIdentity: oldID,
		HostIP:      hostIP,
		OldHostIP:   oldHostIP,
		EncryptKey:  encryptKey,
		Namespace:   namespace,
		PodName:     podName,
	}

	return AgentNotifyMessage{
		Type:         AgentNotifyIPCacheDeleted,
		Notification: notification,
	}
}

// TimeNotification structures agent start notification
type TimeNotification struct {
	Time string `json:"time"`
}

// AgentStartMessage constructs an agent notification message when the agent starts
func StartMessage(t time.Time) AgentNotifyMessage {
	notification := TimeNotification{
		Time: t.String(),
	}

	return AgentNotifyMessage{
		Type:         AgentNotifyStart,
		Notification: notification,
	}
}

// ServiceUpsertNotificationAddr is part of ServiceUpsertNotification
type ServiceUpsertNotificationAddr struct {
	IP   net.IP `json:"ip"`
	Port uint16 `json:"port"`
}

// ServiceUpsertNotification structures service upsert notifications
type ServiceUpsertNotification struct {
	ID uint32 `json:"id"`

	Frontend ServiceUpsertNotificationAddr   `json:"frontend-address"`
	Backends []ServiceUpsertNotificationAddr `json:"backend-addresses"`

	Type          string `json:"type,omitempty"`
	TrafficPolicy string `json:"traffic-policy,omitempty"`

	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,,omitempty"`
}

// ServiceUpsertMessage constructs an agent notification message for service upserts
func ServiceUpsertMessage(
	id uint32,
	frontend ServiceUpsertNotificationAddr,
	backends []ServiceUpsertNotificationAddr,
	svcType, svcTrafficPolicy, svcName, svcNamespace string,
) AgentNotifyMessage {
	notification := ServiceUpsertNotification{
		ID:            id,
		Frontend:      frontend,
		Backends:      backends,
		Type:          svcType,
		TrafficPolicy: svcTrafficPolicy,
		Name:          svcName,
		Namespace:     svcNamespace,
	}

	return AgentNotifyMessage{
		Type:         AgentNotifyServiceUpserted,
		Notification: notification,
	}
}

// ServiceDeleteNotification structures service delete notifications
type ServiceDeleteNotification struct {
	ID uint32 `json:"id"`
}

// ServiceDeleteMessage constructs an agent notification message for service deletions
func ServiceDeleteMessage(id uint32) AgentNotifyMessage {
	notification := ServiceDeleteNotification{
		ID: id,
	}

	return AgentNotifyMessage{
		Type:         AgentNotifyServiceDeleted,
		Notification: notification,
	}
}

const (
	// PolicyIngress is the value of Flags&PolicyNotifyFlagDirection for ingress traffic
	PolicyIngress = 1

	// PolicyEgress is the value of Flags&PolicyNotifyFlagDirection for egress traffic
	PolicyEgress = 2

	// PolicyMatchNone is the value of MatchType indicatating no policy match
	PolicyMatchNone = 0

	// PolicyMatchL3Only is the value of MatchType indicating a L3-only match
	PolicyMatchL3Only = 1

	// PolicyMatchL3L4 is the value of MatchType indicating a L3+L4 match
	PolicyMatchL3L4 = 2

	// PolicyMatchL4Only is the value of MatchType indicating a L4-only match
	PolicyMatchL4Only = 3

	// PolicyMatchAll is the value of MatchType indicating an allow-all match
	PolicyMatchAll = 4
)

type PolicyMatchType int

func (m PolicyMatchType) String() string {
	switch m {
	case PolicyMatchL3Only:
		return "L3-Only"
	case PolicyMatchL3L4:
		return "L3-L4"
	case PolicyMatchL4Only:
		return "L4-Only"
	case PolicyMatchAll:
		return "all"
	case PolicyMatchNone:
		return "none"

	}
	return "unknown"
}
