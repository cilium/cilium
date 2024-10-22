// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package kafka

import (
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
)

type kafkaPlugin struct{}

func (p *kafkaPlugin) NewHandler() api.Handler {
	return &kafkaHandler{}
}

func (p *kafkaPlugin) HelpText() string {
	return `kafka - Kafka metrics
Metrics related to the Kafka protocol

Metrics:
  kafka_requests_total           - Count of Kafka requests by topic and ApiKey.
  kafka_request_duration_seconds - Histogram of Kafka request duration by topic and ApiKey.

Options:` +
		api.ContextOptionsHelp
}

func init() {
	api.DefaultRegistry().Register("kafka", &kafkaPlugin{})
}
