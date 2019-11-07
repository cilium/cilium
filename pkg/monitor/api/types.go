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

const (
	MessageTypeNameDrop    = "drop"
	MessageTypeNameDebug   = "debug"
	MessageTypeNameCapture = "capture"
	MessageTypeNameTrace   = "trace"
	MessageTypeNameL7      = "l7"
	MessageTypeNameAgent   = "agent"
)

type MessageTypeFilter []int

var (
	// MessageTypeNames is a map of all type names
	MessageTypeNames = map[string]int{
		MessageTypeNameDrop:    MessageTypeDrop,
		MessageTypeNameDebug:   MessageTypeDebug,
		MessageTypeNameCapture: MessageTypeCapture,
		MessageTypeNameTrace:   MessageTypeTrace,
		MessageTypeNameL7:      MessageTypeAccessLog,
		MessageTypeNameAgent:   MessageTypeAgent,
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
)

// TraceObservationPoints is a map of all supported trace observation points
var TraceObservationPoints = map[uint8]string{
	TraceToLxc:       "to-endpoint",
	TraceToProxy:     "to-proxy",
	TraceToHost:      "to-host",
	TraceToStack:     "to-stack",
	TraceToOverlay:   "to-overlay",
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

// IPCacheNotificationRepr returns string representation of monitor notification
func IPCacheNotificationRepr(cidr string, id uint32, oldID *uint32, hostIP net.IP, oldHostIP net.IP,
	encryptKey uint8, namespace, podName string) (string, error) {
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

	Type      string `json:"type,omitempty"`
	Name      string `json:"name,omitempty"`
	Namespace string `json:"namespace,,omitempty"`
}

// ServiceUpsertRepr returns string representation of monitor notification
func ServiceUpsertRepr(
	id uint32,
	frontend ServiceUpsertNotificationAddr,
	backends []ServiceUpsertNotificationAddr,
	svcType, svcName, svcNamespace string,
) (string, error) {
	notification := ServiceUpsertNotification{
		ID:        id,
		Frontend:  frontend,
		Backends:  backends,
		Type:      svcType,
		Name:      svcName,
		Namespace: svcNamespace,
	}
	repr, err := json.Marshal(notification)
	return string(repr), err
}

// ServiceDeleteNotification structures service delete notifications
type ServiceDeleteNotification struct {
	ID uint32 `json:"id"`
}

// ServiceDeleteRepr returns string representation of monitor notification
func ServiceDeleteRepr(
	id uint32,
) (string, error) {
	notification := ServiceDeleteNotification{
		ID: id,
	}
	repr, err := json.Marshal(notification)
	return string(repr), err
}
