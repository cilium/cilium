// Copyright 2019 Authors of Hubble
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

package v1

import (
	pb "github.com/cilium/hubble/api/v1/flow"
)

// CompareKafka returns true if both Kafka flows are identical
func CompareKafka(a, b *pb.Kafka) bool {
	return a.ErrorCode == b.ErrorCode &&
		a.ApiVersion == b.ApiVersion &&
		a.ApiKey == b.ApiKey &&
		a.CorrelationId == b.CorrelationId &&
		a.Topic == b.Topic
}
