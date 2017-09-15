/*
Copyright 2016 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package trail

import (
	"strings"
	"testing"

	"github.com/gravitational/trace"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	. "gopkg.in/check.v1"
)

func TestTrail(t *testing.T) { TestingT(t) }

type TrailSuite struct {
}

var _ = Suite(&TrailSuite{})

// TestConversion makes sure we convert all trace supported errors
// to and back from GRPC codes
func (s *TrailSuite) TestConversion(c *C) {
	type TestCase struct {
		Error     error
		Message   string
		Predicate func(error) bool
	}
	testCases := []TestCase{
		{
			Error:     trace.AccessDenied("access denied"),
			Predicate: trace.IsAccessDenied,
		},
		{
			Error:     trace.ConnectionProblem(nil, "problem"),
			Predicate: trace.IsConnectionProblem,
		},
		{
			Error:     trace.NotFound("not found"),
			Predicate: trace.IsNotFound,
		},
		{
			Error:     trace.BadParameter("bad parameter"),
			Predicate: trace.IsBadParameter,
		},
		{
			Error:     trace.CompareFailed("compare failed"),
			Predicate: trace.IsCompareFailed,
		},
		{
			Error:     trace.AccessDenied("denied"),
			Predicate: trace.IsAccessDenied,
		},
		{
			Error:     trace.LimitExceeded("exceeded"),
			Predicate: trace.IsLimitExceeded,
		},
	}
	for i, tc := range testCases {
		comment := Commentf("test case #v", i+1)
		grpcError := ToGRPC(tc.Error)
		c.Assert(grpc.ErrorDesc(grpcError), Equals, tc.Error.Error(), comment)
		out := FromGRPC(grpcError)
		c.Assert(tc.Predicate(out), Equals, true, comment)
	}
}

// TestNil makes sure conversions of nil to and from GRPC are no-op
func (s *TrailSuite) TestNil(c *C) {
	out := FromGRPC(ToGRPC(nil))
	c.Assert(out, IsNil)
}

// TestTraces makes sure we pass traces via metadata and can decode it back
func (s *TrailSuite) TestTraces(c *C) {
	err := trace.BadParameter("param")
	meta := metadata.New(nil)
	SetDebugInfo(err, meta)
	err2 := FromGRPC(ToGRPC(err), meta)
	c.Assert(line(trace.DebugReport(err)), Matches, ".*trail_test.go.*")
	c.Assert(line(trace.DebugReport(err2)), Matches, ".*trail_test.go.*")
}

func line(s string) string {
	return strings.Replace(s, "\n", "", -1)
}
