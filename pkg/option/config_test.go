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

package option

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	. "gopkg.in/check.v1"
)

func (s *OptionSuite) TestValidateIPv6ClusterAllocCIDR(c *C) {
	valid1 := &DaemonConfig{IPv6ClusterAllocCIDR: "fdfd::/64"}
	c.Assert(valid1.validateIPv6ClusterAllocCIDR(), IsNil)
	c.Assert(valid1.IPv6ClusterAllocCIDRBase, Equals, "fdfd::")

	valid2 := &DaemonConfig{IPv6ClusterAllocCIDR: "fdfd:fdfd:fdfd:fdfd:aaaa::/64"}
	c.Assert(valid2.validateIPv6ClusterAllocCIDR(), IsNil)
	c.Assert(valid2.IPv6ClusterAllocCIDRBase, Equals, "fdfd:fdfd:fdfd:fdfd::")

	invalid1 := &DaemonConfig{IPv6ClusterAllocCIDR: "foo"}
	c.Assert(invalid1.validateIPv6ClusterAllocCIDR(), Not(IsNil))

	invalid2 := &DaemonConfig{IPv6ClusterAllocCIDR: "fdfd"}
	c.Assert(invalid2.validateIPv6ClusterAllocCIDR(), Not(IsNil))

	invalid3 := &DaemonConfig{IPv6ClusterAllocCIDR: "fdfd::/32"}
	c.Assert(invalid3.validateIPv6ClusterAllocCIDR(), Not(IsNil))

	invalid4 := &DaemonConfig{}
	c.Assert(invalid4.validateIPv6ClusterAllocCIDR(), Not(IsNil))
}

func TestGetEnvName(t *testing.T) {
	type args struct {
		option string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Normal option",
			args: args{
				option: "foo",
			},
			want: "CILIUM_FOO",
		},
		{
			name: "Capital option",
			args: args{
				option: "FOO",
			},
			want: "CILIUM_FOO",
		},
		{
			name: "with numbers",
			args: args{
				option: "2222",
			},
			want: "CILIUM_2222",
		},
		{
			name: "mix numbers small letters",
			args: args{
				option: "22ada22",
			},
			want: "CILIUM_22ADA22",
		},
		{
			name: "mix numbers small letters and dashes",
			args: args{
				option: "22ada2------2",
			},
			want: "CILIUM_22ADA2______2",
		},
		{
			name: "normal option",
			args: args{
				option: "conntrack-garbage-collector-interval",
			},
			want: "CILIUM_CONNTRACK_GARBAGE_COLLECTOR_INTERVAL",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getEnvName(tt.args.option); got != tt.want {
				t.Errorf("getEnvName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func (s *OptionSuite) TestReadDirConfig(c *C) {
	var dirName string
	type args struct {
		dirName string
	}
	type want struct {
		allSettings        map[string]interface{}
		allSettingsChecker Checker
		err                error
		errChecker         Checker
	}
	tests := []struct {
		name        string
		setupArgs   func() args
		setupWant   func() want
		preTestRun  func()
		postTestRun func()
	}{
		{
			name: "empty configuration",
			preTestRun: func() {
				dirName = c.MkDir()

				fs := flag.NewFlagSet("empty configuration", flag.ContinueOnError)
				viper.BindPFlags(fs)
			},
			setupArgs: func() args {
				return args{
					dirName: dirName,
				}
			},
			setupWant: func() want {
				return want{
					allSettings:        map[string]interface{}{},
					allSettingsChecker: DeepEquals,
					err:                nil,
					errChecker:         Equals,
				}
			},
			postTestRun: func() {
				os.RemoveAll(dirName)
			},
		},
		{
			name: "single file configuration",
			preTestRun: func() {
				dirName = c.MkDir()

				fullPath := filepath.Join(dirName, "test")
				err := ioutil.WriteFile(fullPath, []byte(`"1"
`), os.FileMode(0644))
				c.Assert(err, IsNil)
				fs := flag.NewFlagSet("single file configuration", flag.ContinueOnError)
				fs.String("test", "", "")
				BindEnv("test")
				viper.BindPFlags(fs)

				fmt.Println(fullPath)
			},
			setupArgs: func() args {
				return args{
					dirName: dirName,
				}
			},
			setupWant: func() want {
				return want{
					allSettings:        map[string]interface{}{"test": `"1"`},
					allSettingsChecker: DeepEquals,
					err:                nil,
					errChecker:         Equals,
				}
			},
			postTestRun: func() {
				os.RemoveAll(dirName)
			},
		},
	}
	for _, tt := range tests {
		tt.preTestRun()
		args := tt.setupArgs()
		want := tt.setupWant()
		m, err := ReadDirConfig(args.dirName)
		c.Assert(err, want.errChecker, want.err, Commentf("Test Name: %s", tt.name))
		err = MergeConfig(m)
		c.Assert(err, IsNil)
		c.Assert(viper.AllSettings(), want.allSettingsChecker, want.allSettings, Commentf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func (s *OptionSuite) TestWorkloadsEnabled(c *C) {
	type testDefinition struct {
		config   *DaemonConfig
		expected bool
	}

	tests := []testDefinition{
		{&DaemonConfig{Workloads: []string{}}, false},
		{&DaemonConfig{Workloads: []string{"none"}}, false},
		{&DaemonConfig{Workloads: []string{"none"}}, false},
		{&DaemonConfig{Workloads: []string{"docker", "none"}}, false},
		{&DaemonConfig{Workloads: []string{"docker"}}, true},
		{&DaemonConfig{Workloads: []string{"docker", "crio"}}, true},
		{&DaemonConfig{Workloads: []string{"docker", "nonefalse"}}, true},
	}

	for _, test := range tests {
		if test.config.WorkloadsEnabled() != test.expected {
			c.Errorf("%#v != %#v", test.config.Workloads, test.expected)
		}
	}
}
