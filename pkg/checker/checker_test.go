// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package checker

import (
	"testing"

	check "github.com/cilium/checkmate"
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
