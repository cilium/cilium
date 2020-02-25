// Copyright 2017 Authors of Cilium
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

package kafka

// List of possible Kafka error codes
// Reference: https://kafka.apache.org/protocol#protocol_error_codes
const (
	ErrUnknown                                 = -1
	ErrNone                                    = 0
	ErrOffsetOutOfRange                        = 1
	ErrInvalidMessage                          = 2
	ErrUnknownTopicOrPartition                 = 3
	ErrInvalidMessageSize                      = 4
	ErrLeaderNotAvailable                      = 5
	ErrNotLeaderForPartition                   = 6
	ErrRequestTimeout                          = 7
	ErrBrokerNotAvailable                      = 8
	ErrReplicaNotAvailable                     = 9
	ErrMessageSizeTooLarge                     = 10
	ErrScaleControllerEpoch                    = 11
	ErrOffsetMetadataTooLarge                  = 12
	ErrNetwork                                 = 13
	ErrOffsetLoadInProgress                    = 14
	ErrNoCoordinator                           = 15
	ErrNotCoordinator                          = 16
	ErrInvalidTopic                            = 17
	ErrRecordListTooLarge                      = 18
	ErrNotEnoughReplicas                       = 19
	ErrNotEnoughReplicasAfterAppend            = 20
	ErrInvalidRequiredAcks                     = 21
	ErrIllegalGeneration                       = 22
	ErrInconsistentPartitionAssignmentStrategy = 23
	ErrUnknownParititonAssignmentStrategy      = 24
	ErrUnknownConsumerID                       = 25
	ErrInvalidSessionTimeout                   = 26
	ErrRebalanceInProgress                     = 27
	ErrInvalidCommitOffsetSize                 = 28
	ErrTopicAuthorizationFailed                = 29
	ErrGroupAuthorizationFailed                = 30
	ErrClusterAuthorizationFailed              = 31
	ErrInvalidTimeStamp                        = 32
)
