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

package monitor

import (
	"encoding/json"
	"fmt"

	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

// LogRecordNotify is a proxy access log notification
type LogRecordNotify struct {
	accesslog.LogRecord
}

func (l *LogRecordNotify) direction() string {
	switch l.ObservationPoint {
	case accesslog.Ingress:
		return "<-"
	case accesslog.Egress:
		return "->"
	default:
		return "??"
	}
}

func (l *LogRecordNotify) l7Proto() string {
	if l.HTTP != nil {
		return "http"
	}

	if l.Kafka != nil {
		return "kafka"
	}

	if l.L7 != nil {
		return l.L7.Proto
	}

	return "unknown-l7"
}

// DumpInfo dumps an access log notification
func (l *LogRecordNotify) DumpInfo() {
	fmt.Printf("%s %s %s from %d (%s) to %d (%s), identity %d->%d, verdict %s",
		l.direction(), l.Type, l.l7Proto(), l.SourceEndpoint.ID, l.SourceEndpoint.Labels,
		l.DestinationEndpoint.ID, l.DestinationEndpoint.Labels,
		l.SourceEndpoint.Identity, l.DestinationEndpoint.Identity,
		l.Verdict)

	if http := l.HTTP; http != nil {
		url := ""
		if http.URL != nil {
			url = http.URL.String()
		}

		fmt.Printf(" %s %s => %d\n", http.Method, url, http.Code)
	}

	if kafka := l.Kafka; kafka != nil {
		fmt.Printf(" %s topic %s => %d\n", kafka.APIKey, kafka.Topic.Topic, kafka.ErrorCode)
	}

	if l7 := l.L7; l7 != nil {
		status := ""
		for k, v := range l7.Fields {
			if k == "status" {
				status = v
			} else {
				fmt.Printf(" %s:%s", k, v)
			}
		}
		if status != "" {
			fmt.Printf(" => status:%s", status)
		}
		fmt.Printf("\n")
	}
}

func (l *LogRecordNotify) getJSON() (string, error) {
	v := LogRecordNotifyToVerbose(l)

	ret, err := json.Marshal(v)
	return string(ret), err
}

// DumpJSON prints notification in json format
func (l *LogRecordNotify) DumpJSON() {
	resp, err := l.getJSON()
	if err == nil {
		fmt.Println(resp)
	}
}

// LogRecordNotifyVerbose represents a json notification printed by monitor
type LogRecordNotifyVerbose struct {
	Type             string                     `json:"type"`
	ObservationPoint accesslog.ObservationPoint `json:"observationPoint"`
	FlowType         accesslog.FlowType         `json:"flowType"`
	L7Proto          string                     `json:"l7Proto"`
	SrcEpID          uint64                     `json:"srcEpID"`
	SrcEpLabels      []string                   `json:"srcEpLabels"`
	SrcIdentity      uint64                     `json:"srcIdentity"`
	DstEpID          uint64                     `json:"dstEpID"`
	DstEpLabels      []string                   `json:"dstEpLabels"`
	DstIdentity      uint64                     `json:"dstIdentity"`
	Verdict          accesslog.FlowVerdict      `json:"verdict"`
	HTTP             *accesslog.LogRecordHTTP   `json:"http,omitempty"`
	Kafka            *accesslog.LogRecordKafka  `json:"kafka,omitempty"`
	L7               *accesslog.LogRecordL7     `json:"l7,omitempty"`
}

// LogRecordNotifyToVerbose turns LogRecordNotify into json-friendly Verbose structure
func LogRecordNotifyToVerbose(n *LogRecordNotify) LogRecordNotifyVerbose {
	return LogRecordNotifyVerbose{
		Type:             "logRecord",
		ObservationPoint: n.ObservationPoint,
		FlowType:         n.Type,
		L7Proto:          n.l7Proto(),
		SrcEpID:          n.SourceEndpoint.ID,
		SrcEpLabels:      n.SourceEndpoint.Labels,
		SrcIdentity:      n.SourceEndpoint.Identity,
		DstEpID:          n.DestinationEndpoint.ID,
		DstEpLabels:      n.DestinationEndpoint.Labels,
		DstIdentity:      n.DestinationEndpoint.Identity,
		Verdict:          n.Verdict,
		HTTP:             n.HTTP,
		Kafka:            n.Kafka,
		L7:               n.L7,
	}
}
