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
}
