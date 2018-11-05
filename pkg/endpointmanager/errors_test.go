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

package endpointmanager

import (
	. "gopkg.in/check.v1"
)

func (s *EndpointManagerSuite) TestErrInvalidPrefix_Error(c *C) {
	type args struct {
		err ErrInvalidPrefix
	}
	type want struct {
		errMsg      string
		errMsgCheck Checker
	}
	tests := []struct {
		name      string
		setupArgs func() args
		setupWant func() want
	}{
		{
			name: "random Invalid Prefix",
			setupArgs: func() args {
				return args{
					err: ErrInvalidPrefix{
						InvalidPrefix: "foo",
					},
				}
			},
			setupWant: func() want {
				return want{
					errMsg:      "unknown endpoint prefix 'foo'",
					errMsgCheck: Equals,
				}
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWant()
		errMsg := args.err.Error()
		c.Assert(errMsg, want.errMsgCheck, want.errMsg, Commentf("Test Name: %s", tt.name))
	}
}

func (s *EndpointManagerSuite) TestIsErrUnsupportedID(c *C) {
	type args struct {
		err error
	}
	type want struct {
		bool      bool
		boolCheck Checker
	}
	tests := []struct {
		name      string
		setupArgs func() args
		setupWant func() want
	}{
		{
			name: "is not invalid prefix error",
			setupArgs: func() args {
				return args{
					err: ErrUnsupportedID,
				}
			},
			setupWant: func() want {
				return want{
					bool:      false,
					boolCheck: Equals,
				}
			},
		},
		{
			name: "is invalid prefix error",
			setupArgs: func() args {
				return args{
					err: ErrInvalidPrefix{
						InvalidPrefix: "foo",
					},
				}
			},
			setupWant: func() want {
				return want{
					bool:      true,
					boolCheck: Equals,
				}
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWant()
		errMsg := IsErrInvalidPrefix(args.err)
		c.Assert(errMsg, want.boolCheck, want.bool, Commentf("Test Name: %s", tt.name))
	}
}

func (s *EndpointManagerSuite) TestIsErrInvalidPrefix(c *C) {
	type args struct {
		err error
	}
	type want struct {
		bool      bool
		boolCheck Checker
	}
	tests := []struct {
		name      string
		setupArgs func() args
		setupWant func() want
	}{
		{
			name: "is not unsupported ID error",
			setupArgs: func() args {
				return args{
					err: ErrInvalidPrefix{
						InvalidPrefix: "foo",
					},
				}
			},
			setupWant: func() want {
				return want{
					bool:      false,
					boolCheck: Equals,
				}
			},
		},
		{
			name: "is unsupported ID error",
			setupArgs: func() args {
				return args{
					err: ErrUnsupportedID,
				}
			},
			setupWant: func() want {
				return want{
					bool:      true,
					boolCheck: Equals,
				}
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWant()
		errMsg := IsErrUnsupportedID(args.err)
		c.Assert(errMsg, want.boolCheck, want.bool, Commentf("Test Name: %s", tt.name))
	}
}
