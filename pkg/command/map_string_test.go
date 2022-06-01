// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package command

import (
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
)

func TestGetStringMapString(t *testing.T) {
	expectedResult := map[string]string{
		"k1": "v1",
		"k2": "v2",
	}
	type args struct {
		key   string
		value string
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "valid json format",
			args: args{
				key:   "FOO_BAR",
				value: `{"k1":"v1","k2":"v2"}`,
			},
			want:    expectedResult,
			wantErr: assert.NoError,
		},
		{
			name: "valid empty json",
			args: args{
				key:   "FOO_BAR",
				value: "{}",
			},
			want:    map[string]string{},
			wantErr: assert.NoError,
		},
		{
			name: "invalid json format with extra comma at the end",
			args: args{
				key:   "FOO_BAR",
				value: `{"k1":"v1","k2":"v2",}`,
			},
			want:    map[string]string{},
			wantErr: assertErrorString("invalid character '}' looking for beginning of object key string"),
		},
		{
			name: "valid single kv format",
			args: args{
				key:   "FOO_BAR",
				value: "k1=v1",
			},
			want:    map[string]string{"k1": "v1"},
			wantErr: assert.NoError,
		},
		{
			name: "valid kv format",
			args: args{
				key:   "FOO_BAR",
				value: "k1=v1,k2=v2",
			},
			want:    expectedResult,
			wantErr: assert.NoError,
		},
		{
			name: "valid kv format with @",
			args: args{
				key:   "FOO_BAR",
				value: "k1=v1,k2=test@test.com",
			},
			want: map[string]string{
				"k1": "v1",
				"k2": "test@test.com",
			},
			wantErr: assert.NoError,
		},
		{
			name: "valid kv format with empty value",
			args: args{
				key:   "FOO_BAR",
				value: "k1=,k2=v2",
			},
			want: map[string]string{
				"k1": "",
				"k2": "v2",
			},
			wantErr: assert.NoError,
		},
		{
			name: "valid kv format with comma in value",
			args: args{
				key:   "API_RATE_LIMIT",
				value: "endpoint-create=rate-limit:10/s,rate-burst:10,parallel-requests:10,auto-adjust:true,endpoint-delete=rate-limit:10/s,rate-burst:10,parallel-requests:10,auto-adjust:true",
			},
			want: map[string]string{
				"endpoint-create": "rate-limit:10/s,rate-burst:10,parallel-requests:10,auto-adjust:true",
				"endpoint-delete": "rate-limit:10/s,rate-burst:10,parallel-requests:10,auto-adjust:true",
			},
			wantErr: assert.NoError,
		},
		{
			name: "another valid kv format with comma in value",
			args: args{
				key:   "AWS_INSTANCE_LIMIT_MAPPING",
				value: "c6a.2xlarge=4,15,15",
			},
			want: map[string]string{
				"c6a.2xlarge": "4,15,15",
			},
			wantErr: assert.NoError,
		},
		{
			name: "valid kv format with forward slash",
			args: args{
				key:   "FOO_BAR",
				value: "kubernetes.io/cluster/piano-eks-general-blue-01=owned,kubernetes.io/role/internal-elb=1",
			},
			want: map[string]string{
				"kubernetes.io/cluster/piano-eks-general-blue-01": "owned",
				"kubernetes.io/role/internal-elb":                 "1",
			},
			wantErr: assert.NoError,
		},
		{
			name: "valid kv format with hyphens",
			args: args{
				key:   "FOO_BAR",
				value: "cluster=my-cluster",
			},
			want: map[string]string{
				"cluster": "my-cluster",
			},
			wantErr: assert.NoError,
		},
		{
			name: "invalid kv format with extra comma",
			args: args{
				key:   "FOO_BAR",
				value: "k1=v1,k2=v2,",
			},
			want:    map[string]string{},
			wantErr: assertErrorString("'k1=v1,k2=v2,' is not formatted as key=value,key1=value1"),
		},
		{
			name: "invalid kv format with extra equal",
			args: args{
				key:   "FOO_BAR",
				value: "k1=v1,k2==v2",
			},
			want:    map[string]string{},
			wantErr: assertErrorString("'k1=v1,k2==v2' is not formatted as key=value,key1=value1"),
		},
		{
			name: "invalid kv format with wrong space in between",
			args: args{
				key:   "FOO_BAR",
				value: "k1=v1, k2=v2",
			},
			want:    map[string]string{},
			wantErr: assertErrorString("'k1=v1, k2=v2' is not formatted as key=value,key1=value1"),
		},
		{
			name: "malformed json format",
			args: args{
				key:   "FOO_BAR",
				value: `{"k1": "v1",=sdlkfj`,
			},
			want:    map[string]string{},
			wantErr: assertErrorString("invalid character '=' looking for beginning of object key string"),
		},
		{
			name: "staring with valid json beginning value e.g. t, f, n, 0, -, \"",
			args: args{
				key:   "FOO_BAR",
				value: "this is a sentence used in test",
			},
			want:    map[string]string{},
			wantErr: assertErrorString("'this is a sentence used in test' is not formatted as key=value,key1=value1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()
			viper.AutomaticEnv()
			t.Setenv(strings.ToUpper(tt.args.key), tt.args.value)
			v, err := GetStringMapStringE(viper.GetViper(), strings.ToLower(tt.args.key))
			tt.wantErr(t, err)
			assert.Equal(t, tt.want, v)
		})
	}
}

func TestGetStringMapStringConversion(t *testing.T) {
	viper.Reset()
	viper.Set("foo_bar", struct{}{})
	v, err := GetStringMapStringE(viper.GetViper(), "foo_bar")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unable to cast struct {}{} of type struct {} to map[string]string")
	assert.Equal(t, map[string]string{}, v)
}

func Test_isValidKeyValuePair(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "valid format with one pair",
			args: args{
				str: "k1=v1",
			},
			want: true,
		},
		{
			name: "valid format with hyphen in k and v",
			args: args{
				str: "k-1=v-1,k-2=v-2",
			},
			want: true,
		},
		{
			name: "valid format with multiple hyphens",
			args: args{
				str: "Cluster=piano-eks-general-blue-01",
			},
			want: true,
		},
		{
			name: "valid format with colon",
			args: args{
				str: "consul.address=127.0.0.1:8500",
			},
			want: true,
		},
		{
			name: "valid format with forward slash",
			args: args{
				str: "kubernetes.io/cluster/piano-eks-general-blue-01=owned",
			},
			want: true,
		},

		{
			name: "valid format with multiple pairs",
			args: args{
				str: "k1=v1,k2=v2,k3=v3,k4=v4,k4=v4,k4=v4",
			},
			want: true,
		},
		{
			name: "empty value",
			args: args{
				str: "",
			},
			want: true,
		},
		{
			name: "space in between",
			args: args{
				str: "k1=v1, k2=v2",
			},
			want: false,
		},
		{
			name: "insufficient value",
			args: args{
				str: "k1=v1,k2,=v2",
			},
			want: false,
		},
		{
			name: "no pair at all",
			args: args{
				str: "here is the test",
			},
			want: false,
		},
		{
			name: "ending with command",
			args: args{
				str: "k1=v1,k2=v2,",
			},
			want: false,
		},
		{
			name: "ending with equal",
			args: args{
				str: "k1=v1,k2=v2=",
			},
			want: false,
		},
		{
			name: "kv separator as space",
			args: args{
				str: "k1=v1 k2=v2=",
			},
			want: false,
		},
		{
			name: "space in key",
			args: args{
				str: "k1=v1, k2=v2",
			},
			want: false,
		},
		{
			name: "space in value",
			args: args{
				str: "k1=v1,k2= v2",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, isValidKeyValuePair(tt.args.str), "isValidKeyValuePair(%v)", tt.args.str)
		})
	}
}

func assertErrorString(errString string) assert.ErrorAssertionFunc {
	return func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
		return assert.EqualError(t, err, errString, msgAndArgs)
	}
}
