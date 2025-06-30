// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package kafka

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_kafkaPlugin_HelpText(t *testing.T) {
	plugin := &kafkaPlugin{}
	expected := `kafka - Kafka metrics
Metrics related to the Kafka protocol

Metrics:
  kafka_requests_total           - Count of Kafka requests by topic and ApiKey.
  kafka_request_duration_seconds - Histogram of Kafka request duration by topic and ApiKey.

Options:
 sourceContext             ::= identifier , { "|", identifier }
 destinationContext        ::= identifier , { "|", identifier }
 sourceEgressContext       ::= identifier , { "|", identifier }
 sourceIngressContext      ::= identifier , { "|", identifier }
 destinationEgressContext  ::= identifier , { "|", identifier }
 destinationIngressContext ::= identifier , { "|", identifier }
 labels                    ::= label , { ",", label }
 identifier                ::= identity | namespace | pod | pod-name | dns | ip | reserved-identity | workload | workload-name | app
 label                     ::= source_ip | source_pod | source_namespace | source_workload | source_workload_kind | source_app | destination_ip | destination_pod | destination_namespace | destination_workload | destination_workload_kind | destination_app | traffic_direction
`
	assert.Equal(t, expected, plugin.HelpText())
}
