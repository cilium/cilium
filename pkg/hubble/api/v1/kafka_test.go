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

// +build !privileged_tests

package v1

import (
	"testing"

	pb "github.com/cilium/cilium/api/v1/flow"

	"github.com/stretchr/testify/assert"
)

func TestCompareKafka(t *testing.T) {
	type testDef struct {
		a      *pb.Kafka
		b      *pb.Kafka
		result bool
	}

	matrix := []testDef{
		{a: &pb.Kafka{}, b: &pb.Kafka{}, result: true},
		{a: &pb.Kafka{ErrorCode: 10}, b: &pb.Kafka{ErrorCode: 10}, result: true},
		{a: &pb.Kafka{ErrorCode: 10}, b: &pb.Kafka{ErrorCode: 20}, result: false},
		{a: &pb.Kafka{ErrorCode: 10, ApiKey: "foo"}, b: &pb.Kafka{ErrorCode: 10, ApiKey: "foo"}, result: true},
		{a: &pb.Kafka{ErrorCode: 10, ApiKey: "foo"}, b: &pb.Kafka{ErrorCode: 10, ApiKey: "bar"}, result: false},
		{a: &pb.Kafka{ApiVersion: 10}, b: &pb.Kafka{ApiVersion: 10}, result: true},
		{a: &pb.Kafka{ApiVersion: 10}, b: &pb.Kafka{ApiVersion: 20}, result: false},
		{a: &pb.Kafka{CorrelationId: 10}, b: &pb.Kafka{CorrelationId: 10}, result: true},
		{a: &pb.Kafka{CorrelationId: 10}, b: &pb.Kafka{CorrelationId: 20}, result: false},
		{a: &pb.Kafka{ErrorCode: 10, Topic: "foo"}, b: &pb.Kafka{ErrorCode: 10, Topic: "foo"}, result: true},
		{a: &pb.Kafka{ErrorCode: 10, Topic: "foo"}, b: &pb.Kafka{ErrorCode: 10, Topic: "bar"}, result: false},
	}

	for _, test := range matrix {
		assert.EqualValues(t, CompareKafka(test.a, test.b), test.result)
	}

}
