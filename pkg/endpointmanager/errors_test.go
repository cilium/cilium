// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointmanager

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrInvalidPrefix_Error(t *testing.T) {
	setupEndpointManagerSuite(t)

	type args struct {
		err ErrInvalidPrefix
	}
	type want struct {
		errMsg string
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
					errMsg: "unknown endpoint prefix 'foo'",
				}
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWant()
		errMsg := args.err.Error()
		require.Equalf(t, want.errMsg, errMsg, "Test Name: %s", tt.name)
	}
}

func TestIsErrUnsupportedID(t *testing.T) {
	setupEndpointManagerSuite(t)

	type args struct {
		err error
	}
	type want struct {
		bool bool
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
					bool: false,
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
					bool: true,
				}
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWant()
		errMsg := IsErrInvalidPrefix(args.err)
		require.Equalf(t, want.bool, errMsg, "Test Name: %s", tt.name)
	}
}

func TestIsErrInvalidPrefix(t *testing.T) {
	setupEndpointManagerSuite(t)

	type args struct {
		err error
	}
	type want struct {
		bool bool
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
					bool: false,
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
					bool: true,
				}
			},
		},
	}
	for _, tt := range tests {
		args := tt.setupArgs()
		want := tt.setupWant()
		errMsg := IsErrUnsupportedID(args.err)
		require.Equalf(t, want.bool, errMsg, "Test Name: %s", tt.name)
	}
}
