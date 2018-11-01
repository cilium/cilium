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

// +build !privileged_tests

package checker

import (
	"testing"

	"gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	check.TestingT(t)
}

type CheckerSuite struct{}

var _ = check.Suite(&CheckerSuite{})

func (s *CheckerSuite) TestDeepEqualsCheck(c *check.C) {
	names := []string{"a", "b"}
	type args struct {
		params []interface{}
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "args of basic type are equal",
			args: args{
				params: []interface{}{1, 1},
			},
			want: true,
		},
		{
			name: "args of basic type are not equal",
			args: args{
				params: []interface{}{1, 2},
			},
			want: false,
		},
		{
			name: "maps are deeply equal",
			args: args{
				params: []interface{}{
					map[string]string{
						"foo": "bar",
					},
					map[string]string{
						"foo": "bar",
					},
				},
			},
			want: true,
		},
		{
			name: "maps are not equal",
			args: args{
				params: []interface{}{
					map[string]string{
						"foo": "ar",
					},
					map[string]string{
						"foo": "bar",
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		equal, err := DeepEquals.Check(tt.args.params, names)
		c.Assert(equal, check.Equals, tt.want)
		c.Assert(equal, check.Equals, err == "")
	}

	equal, err := DeepEquals.Check([]interface{}{1, 1}, []string{"a"})
	c.Assert(equal, check.Equals, false)
	c.Assert(err, check.NotNil)

	equal, err = DeepEquals.Check([]interface{}{1}, []string{"a"})
	c.Assert(equal, check.Equals, false)
	c.Assert(err, check.NotNil)
}
