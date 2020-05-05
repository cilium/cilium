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

func TestCompareHTTP(t *testing.T) {
	type testDef struct {
		a      *pb.HTTP
		b      *pb.HTTP
		result bool
	}

	matrix := []testDef{
		{a: &pb.HTTP{}, b: &pb.HTTP{}, result: true},
		{a: &pb.HTTP{Code: 10}, b: &pb.HTTP{Code: 10}, result: true},
		{a: &pb.HTTP{Code: 10}, b: &pb.HTTP{Code: 20}, result: false},
		{a: &pb.HTTP{Method: "GET"}, b: &pb.HTTP{Method: "GET"}, result: true},
		{a: &pb.HTTP{Method: "GET"}, b: &pb.HTTP{Method: "POST"}, result: false},
		{a: &pb.HTTP{Method: "GET", Url: "/path"}, b: &pb.HTTP{Method: "GET", Url: "/path"}, result: true},
		{a: &pb.HTTP{Method: "GET", Url: "/path"}, b: &pb.HTTP{Method: "GET", Url: "/other"}, result: false},
		{a: &pb.HTTP{Protocol: "HTTP"}, b: &pb.HTTP{Protocol: "HTTP"}, result: true},
		{a: &pb.HTTP{Protocol: "HTTP"}, b: &pb.HTTP{Protocol: "HTTP/2"}, result: false},
		// HTTP header must be ignored in comparison
		{a: &pb.HTTP{Method: "GET", Headers: []*pb.HTTPHeader{{Key: "foo", Value: "value"}}}, b: &pb.HTTP{Method: "GET"}, result: true},
	}

	for _, test := range matrix {
		assert.EqualValues(t, LooseCompareHTTP(test.a, test.b), test.result)
	}

}
