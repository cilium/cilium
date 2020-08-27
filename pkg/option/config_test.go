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
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/google/go-cmp/cmp"
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

func (s *OptionSuite) TestBindEnv(c *C) {
	optName1 := "foo-bar"
	os.Setenv("LEGACY_FOO_BAR", "legacy")
	os.Setenv(getEnvName(optName1), "new")
	BindEnvWithLegacyEnvFallback(optName1, "LEGACY_FOO_BAR")
	c.Assert(viper.GetString(optName1), Equals, "new")

	optName2 := "bar-foo"
	BindEnvWithLegacyEnvFallback(optName2, "LEGACY_FOO_BAR")
	c.Assert(viper.GetString(optName2), Equals, "legacy")

	viper.Reset()
}

func (s *OptionSuite) TestEnabledFunctions(c *C) {
	d := &DaemonConfig{}
	c.Assert(d.IPv4Enabled(), Equals, false)
	c.Assert(d.IPv6Enabled(), Equals, false)
	d = &DaemonConfig{EnableIPv4: true}
	c.Assert(d.IPv4Enabled(), Equals, true)
	c.Assert(d.IPv6Enabled(), Equals, false)
	d = &DaemonConfig{EnableIPv6: true}
	c.Assert(d.IPv4Enabled(), Equals, false)
	c.Assert(d.IPv6Enabled(), Equals, true)
	d = &DaemonConfig{}
	c.Assert(d.IPAMMode(), Equals, "")
	d = &DaemonConfig{IPAM: ipamOption.IPAMENI}
	c.Assert(d.IPAMMode(), Equals, ipamOption.IPAMENI)
}

func (s *OptionSuite) TestLocalAddressExclusion(c *C) {
	d := &DaemonConfig{}
	err := d.parseExcludedLocalAddresses([]string{"1.1.1.1/32", "3.3.3.0/24", "f00d::1/128"})
	c.Assert(err, IsNil)

	c.Assert(d.IsExcludedLocalAddress(net.ParseIP("1.1.1.1")), Equals, true)
	c.Assert(d.IsExcludedLocalAddress(net.ParseIP("1.1.1.2")), Equals, false)
	c.Assert(d.IsExcludedLocalAddress(net.ParseIP("3.3.3.1")), Equals, true)
	c.Assert(d.IsExcludedLocalAddress(net.ParseIP("f00d::1")), Equals, true)
	c.Assert(d.IsExcludedLocalAddress(net.ParseIP("f00d::2")), Equals, false)
}

func (s *OptionSuite) TestEndpointStatusIsEnabled(c *C) {

	d := DaemonConfig{}
	d.EndpointStatus = map[string]struct{}{EndpointStatusHealth: {}, EndpointStatusPolicy: {}}
	c.Assert(d.EndpointStatusIsEnabled(EndpointStatusHealth), Equals, true)
	c.Assert(d.EndpointStatusIsEnabled(EndpointStatusPolicy), Equals, true)
	c.Assert(d.EndpointStatusIsEnabled(EndpointStatusLog), Equals, false)
}

func TestCheckMapSizeLimits(t *testing.T) {
	type sizes struct {
		CTMapEntriesGlobalTCP int
		CTMapEntriesGlobalAny int
		NATMapEntriesGlobal   int
		PolicyMapEntries      int
		LBMapEntries          int
		FragmentsMapEntries   int
		NeighMapEntriesGlobal int
		SockRevNatEntries     int
		WantErr               bool
	}
	tests := []struct {
		name string
		d    *DaemonConfig
		want sizes
	}{
		{
			name: "default map sizes",
			d: &DaemonConfig{
				CTMapEntriesGlobalTCP: CTMapEntriesGlobalTCPDefault,
				CTMapEntriesGlobalAny: CTMapEntriesGlobalAnyDefault,
				NATMapEntriesGlobal:   NATMapEntriesGlobalDefault,
				PolicyMapEntries:      16384,
				LBMapEntries:          65536,
				FragmentsMapEntries:   defaults.FragmentsMapEntries,
				NeighMapEntriesGlobal: NATMapEntriesGlobalDefault,
				SockRevNatEntries:     SockRevNATMapEntriesDefault,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: CTMapEntriesGlobalTCPDefault,
				CTMapEntriesGlobalAny: CTMapEntriesGlobalAnyDefault,
				NATMapEntriesGlobal:   NATMapEntriesGlobalDefault,
				PolicyMapEntries:      16384,
				LBMapEntries:          65536,
				FragmentsMapEntries:   defaults.FragmentsMapEntries,
				NeighMapEntriesGlobal: NATMapEntriesGlobalDefault,
				SockRevNatEntries:     SockRevNATMapEntriesDefault,
				WantErr:               false,
			},
		},
		{
			name: "arbitrary map sizes within range",
			d: &DaemonConfig{
				CTMapEntriesGlobalTCP: 20000,
				CTMapEntriesGlobalAny: 18000,
				NATMapEntriesGlobal:   2048,
				PolicyMapEntries:      512,
				LBMapEntries:          1 << 14,
				SockRevNatEntries:     18000,
				FragmentsMapEntries:   2 << 14,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: 20000,
				CTMapEntriesGlobalAny: 18000,
				NATMapEntriesGlobal:   2048,
				PolicyMapEntries:      512,
				LBMapEntries:          1 << 14,
				SockRevNatEntries:     18000,
				FragmentsMapEntries:   2 << 14,
				WantErr:               false,
			},
		},
		{
			name: "CT TCP map size below range",
			d: &DaemonConfig{
				CTMapEntriesGlobalTCP: LimitTableMin - 1,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: LimitTableMin - 1,
				WantErr:               true,
			},
		},
		{
			name: "CT TCP map size above range",
			d: &DaemonConfig{
				CTMapEntriesGlobalTCP: LimitTableMax + 1,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: LimitTableMax + 1,
				WantErr:               true,
			},
		},
		{
			name: "CT Any map size below range",
			d: &DaemonConfig{
				CTMapEntriesGlobalAny: LimitTableMin - 1,
			},
			want: sizes{
				CTMapEntriesGlobalAny: LimitTableMin - 1,
				WantErr:               true,
			},
		},
		{
			name: "CT Any map size above range",
			d: &DaemonConfig{
				CTMapEntriesGlobalAny: LimitTableMax + 1,
			},
			want: sizes{
				CTMapEntriesGlobalAny: LimitTableMax + 1,
				WantErr:               true,
			},
		},
		{
			name: "NAT map size below range",
			d: &DaemonConfig{
				NATMapEntriesGlobal: LimitTableMin - 1,
			},
			want: sizes{
				NATMapEntriesGlobal: LimitTableMin - 1,
				WantErr:             true,
			},
		},
		{
			name: "NAT map size above range",
			d: &DaemonConfig{
				NATMapEntriesGlobal: LimitTableMax + 1,
			},
			want: sizes{
				NATMapEntriesGlobal: LimitTableMax + 1,
				WantErr:             true,
			},
		},
		{
			name: "NAT map auto sizing with default size",
			d: &DaemonConfig{
				CTMapEntriesGlobalTCP: 2048,
				CTMapEntriesGlobalAny: 4096,
				NATMapEntriesGlobal:   NATMapEntriesGlobalDefault,
				SockRevNatEntries:     4096,
				PolicyMapEntries:      16384,
				LBMapEntries:          65536,
				FragmentsMapEntries:   defaults.FragmentsMapEntries,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: 2048,
				CTMapEntriesGlobalAny: 4096,
				NATMapEntriesGlobal:   (2048 + 4096) * 2 / 3,
				SockRevNatEntries:     4096,
				PolicyMapEntries:      16384,
				LBMapEntries:          65536,
				FragmentsMapEntries:   defaults.FragmentsMapEntries,
				WantErr:               false,
			},
		},
		{
			name: "NAT map auto sizing outside of range",
			d: &DaemonConfig{
				CTMapEntriesGlobalTCP: 2048,
				CTMapEntriesGlobalAny: 4096,
				NATMapEntriesGlobal:   8192,
			},
			want: sizes{
				CTMapEntriesGlobalTCP: 2048,
				CTMapEntriesGlobalAny: 4096,
				NATMapEntriesGlobal:   8192,
				WantErr:               true,
			},
		},
		{
			name: "Policy map size below range",
			d: &DaemonConfig{
				PolicyMapEntries: PolicyMapMin - 1,
			},
			want: sizes{
				PolicyMapEntries: PolicyMapMin - 1,
				WantErr:          true,
			},
		},
		{
			name: "Policy map size above range",
			d: &DaemonConfig{
				PolicyMapEntries: PolicyMapMax + 1,
			},
			want: sizes{
				PolicyMapEntries: PolicyMapMax + 1,
				WantErr:          true,
			},
		},
		{
			name: "Fragments map size below range",
			d: &DaemonConfig{
				FragmentsMapEntries: FragmentsMapMin - 1,
			},
			want: sizes{
				FragmentsMapEntries: FragmentsMapMin - 1,
				WantErr:             true,
			},
		},
		{
			name: "Fragments map size above range",
			d: &DaemonConfig{
				FragmentsMapEntries: FragmentsMapMax + 1,
			},
			want: sizes{
				FragmentsMapEntries: FragmentsMapMax + 1,
				WantErr:             true,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.d.checkMapSizeLimits()

			got := sizes{
				CTMapEntriesGlobalTCP: tt.d.CTMapEntriesGlobalTCP,
				CTMapEntriesGlobalAny: tt.d.CTMapEntriesGlobalAny,
				NATMapEntriesGlobal:   tt.d.NATMapEntriesGlobal,
				PolicyMapEntries:      tt.d.PolicyMapEntries,
				LBMapEntries:          tt.d.LBMapEntries,
				FragmentsMapEntries:   tt.d.FragmentsMapEntries,
				NeighMapEntriesGlobal: tt.d.NeighMapEntriesGlobal,
				SockRevNatEntries:     tt.d.SockRevNatEntries,
				WantErr:               err != nil,
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("DaemonConfig.checkMapSizeLimits mismatch for '%s' (-want +got):\n%s", tt.name, diff)

				if err != nil {
					t.Error(err)
				}
			}
		})
	}
}

func TestCheckIPv4NativeRoutingCIDR(t *testing.T) {
	tests := []struct {
		name    string
		d       *DaemonConfig
		wantErr bool
	}{
		{
			name: "with native routing cidr",
			d: &DaemonConfig{
				Masquerade:            true,
				Tunnel:                TunnelDisabled,
				IPAM:                  ipamOption.IPAMAzure,
				ipv4NativeRoutingCIDR: cidr.MustParseCIDR("10.127.64.0/18"),
				EnableIPv4:            true,
			},
			wantErr: false,
		},
		{
			name: "without native routing cidr and no masquerade",
			d: &DaemonConfig{
				Masquerade: false,
				Tunnel:     TunnelDisabled,
				IPAM:       ipamOption.IPAMAzure,
				EnableIPv4: true,
			},
			wantErr: false,
		},
		{
			name: "without native routing cidr and tunnel enabled",
			d: &DaemonConfig{
				Masquerade: true,
				Tunnel:     TunnelVXLAN,
				IPAM:       ipamOption.IPAMAzure,
				EnableIPv4: true,
			},
			wantErr: false,
		},
		{
			name: "without native routing cidr and tunnel enabled",
			d: &DaemonConfig{
				Masquerade: true,
				Tunnel:     TunnelDisabled,
				IPAM:       ipamOption.IPAMENI,
				EnableIPv4: true,
			},
			wantErr: false,
		},
		{
			name: "without native routing cidr and with masquerade and tunnel disabled and ipam not eni",
			d: &DaemonConfig{
				Masquerade: true,
				Tunnel:     TunnelDisabled,
				IPAM:       ipamOption.IPAMAzure,
				EnableIPv4: true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.d.checkIPv4NativeRoutingCIDR()
			if tt.wantErr && err == nil {
				t.Error("expected error, but got nil")
			}
		})
	}

}

func Test_populateNodePortRange(t *testing.T) {
	type want struct {
		wantMin int
		wantMax int
		wantErr bool
	}
	tests := []struct {
		name       string
		want       want
		preTestRun func()
	}{
		{
			name: "NodePortRange is valid",
			want: want{
				wantMin: 23,
				wantMax: 24,
				wantErr: false,
			},
			preTestRun: func() {
				viper.Reset()
				viper.Set(NodePortRange, []string{"23", "24"})
			},
		},
		{
			name: "NodePortRange not set in viper",
			want: want{
				wantMin: NodePortMinDefault,
				wantMax: NodePortMaxDefault,
				wantErr: false,
			},
			preTestRun: func() {
				viper.Reset()

				fs := flag.NewFlagSet(NodePortRange, flag.ContinueOnError)
				fs.StringSlice(
					NodePortRange,
					[]string{
						fmt.Sprintf("%d", NodePortMinDefault),
						fmt.Sprintf("%d", NodePortMaxDefault),
					},
					"")

				BindEnv(NodePortRange)
				viper.BindPFlags(fs)
			},
		},
		{
			name: "NodePortMin greater than NodePortMax",
			want: want{
				wantMin: 666,
				wantMax: 555,
				wantErr: true,
			},
			preTestRun: func() {
				viper.Reset()
				viper.Set(NodePortRange, []string{"666", "555"})
			},
		},
		{
			name: "NodePortMin equal NodePortMax",
			want: want{
				wantMin: 666,
				wantMax: 666,
				wantErr: true,
			},
			preTestRun: func() {
				viper.Reset()
				viper.Set(NodePortRange, []string{"666", "666"})
			},
		},
		{
			name: "NodePortMin not a number",
			want: want{
				wantMin: 0,
				wantMax: 0,
				wantErr: true,
			},
			preTestRun: func() {
				viper.Reset()
				viper.Set(NodePortRange, []string{"aaa", "0"})
			},
		},
		{
			name: "NodePortMax not a number",
			want: want{
				wantMin: 1024,
				wantMax: 0,
				wantErr: true,
			},
			preTestRun: func() {
				viper.Reset()
				viper.Set(NodePortRange, []string{"1024", "aaa"})
			},
		},
		{
			name: "NodePortRange slice length not equal 2",
			want: want{
				wantMin: 0,
				wantMax: 0,
				wantErr: true,
			},
			preTestRun: func() {
				viper.Reset()

				delete(RegisteredOptions, NodePortRange)

				fs := flag.NewFlagSet(NodePortRange, flag.ContinueOnError)
				fs.StringSlice(
					NodePortRange,
					[]string{
						fmt.Sprintf("%d", NodePortMinDefault),
						fmt.Sprintf("%d", NodePortMaxDefault),
					},
					"")

				BindEnv(NodePortRange)
				viper.BindPFlags(fs)

				viper.Set(NodePortRange, []string{"1024"})
			},
		},
		{
			// We simply just want to warn the user in this case.
			name: "NodePortRange passed as empty",
			want: want{
				wantMin: 0,
				wantMax: 0,
				wantErr: false,
			},
			preTestRun: func() {
				viper.Reset()

				delete(RegisteredOptions, NodePortRange)

				fs := flag.NewFlagSet(NodePortRange, flag.ContinueOnError)
				fs.StringSlice(
					NodePortRange,
					[]string{}, // Explicitly has no defaults.
					"")

				BindEnv(NodePortRange)
				viper.BindPFlags(fs)

				viper.Set(NodePortRange, []string{})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.preTestRun()

			d := &DaemonConfig{}
			err := d.populateNodePortRange()

			got := want{
				wantMin: d.NodePortMin,
				wantMax: d.NodePortMax,
				wantErr: err != nil,
			}

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DaemonConfig.populateNodePortRange = got %v, want %v", got, tt.want)
			}
		})
	}
}

func (s *OptionSuite) TestGetDefaultMonitorQueueSize(c *C) {
	c.Assert(getDefaultMonitorQueueSize(4), Equals, 4*defaults.MonitorQueueSizePerCPU)
	c.Assert(getDefaultMonitorQueueSize(1000), Equals, defaults.MonitorQueueSizePerCPUMaximum)
}

func (s *OptionSuite) TestEndpointStatusValues(c *C) {
	c.Assert(len(EndpointStatusValues()), Not(Equals), 0)
	c.Assert(len(EndpointStatusValuesMap()), Not(Equals), 0)
	for _, v := range EndpointStatusValues() {
		_, ok := EndpointStatusValuesMap()[v]
		c.Assert(ok, Equals, true)
	}
}

const (
	_   = iota
	KiB = 1 << (10 * iota)
	MiB
	GiB
)

func TestBPFMapSizeCalculation(t *testing.T) {
	type sizes struct {
		CTMapSizeTCP      int
		CTMapSizeAny      int
		NATMapSize        int
		NeighMapSize      int
		SockRevNatMapSize int
	}
	tests := []struct {
		name        string
		totalMemory uint64
		ratio       float64
		want        sizes
		preTestRun  func()
	}{
		{
			name: "static default sizes",
			// zero memory and ratio: skip calculateDynamicBPFMapSizes
			want: sizes{
				CTMapSizeTCP:      CTMapEntriesGlobalTCPDefault,
				CTMapSizeAny:      CTMapEntriesGlobalAnyDefault,
				NATMapSize:        NATMapEntriesGlobalDefault,
				NeighMapSize:      NATMapEntriesGlobalDefault,
				SockRevNatMapSize: SockRevNATMapEntriesDefault,
			},
			preTestRun: func() {
				viper.Set(CTMapEntriesGlobalTCPName, CTMapEntriesGlobalTCPDefault)
				viper.Set(CTMapEntriesGlobalAnyName, CTMapEntriesGlobalAnyDefault)
				viper.Set(NATMapEntriesGlobalName, NATMapEntriesGlobalDefault)
				// Neigh table has the same number of entries as NAT Map has.
				viper.Set(NeighMapEntriesGlobalName, NATMapEntriesGlobalDefault)
				viper.Set(SockRevNatEntriesName, SockRevNATMapEntriesDefault)
			},
		},
		{
			name: "static, non-default sizes inside range",
			// zero memory and ratio: skip calculateDynamicBPFMapSizes
			want: sizes{
				CTMapSizeTCP:      CTMapEntriesGlobalTCPDefault + 128,
				CTMapSizeAny:      CTMapEntriesGlobalAnyDefault - 64,
				NATMapSize:        NATMapEntriesGlobalDefault + 256,
				NeighMapSize:      NATMapEntriesGlobalDefault + 256,
				SockRevNatMapSize: SockRevNATMapEntriesDefault + 256,
			},
			preTestRun: func() {
				viper.Set(CTMapEntriesGlobalTCPName, CTMapEntriesGlobalTCPDefault+128)
				viper.Set(CTMapEntriesGlobalAnyName, CTMapEntriesGlobalAnyDefault-64)
				viper.Set(NATMapEntriesGlobalName, NATMapEntriesGlobalDefault+256)
				// Neigh table has the same number of entries as NAT Map has.
				viper.Set(NeighMapEntriesGlobalName, NATMapEntriesGlobalDefault+256)
				viper.Set(SockRevNatEntriesName, SockRevNATMapEntriesDefault+256)
			},
		},
		{
			name:        "dynamic size without any static sizes (512MB, 0.25%)",
			totalMemory: 512 * MiB,
			ratio:       0.0025,
			want: sizes{
				CTMapSizeTCP:      LimitTableAutoGlobalTCPMin,
				CTMapSizeAny:      LimitTableAutoGlobalAnyMin,
				NATMapSize:        LimitTableAutoNatGlobalMin,
				NeighMapSize:      LimitTableAutoNatGlobalMin,
				SockRevNatMapSize: LimitTableAutoSockRevNatMin,
			},
		},
		{
			name:        "dynamic size without any static sizes (1GiB, 0.25%)",
			totalMemory: 1 * GiB,
			ratio:       0.0025,
			want: sizes{
				CTMapSizeTCP:      LimitTableAutoGlobalTCPMin,
				CTMapSizeAny:      LimitTableAutoGlobalAnyMin,
				NATMapSize:        LimitTableAutoNatGlobalMin,
				NeighMapSize:      LimitTableAutoNatGlobalMin,
				SockRevNatMapSize: LimitTableAutoSockRevNatMin,
			},
		},
		{
			name:        "dynamic size without any static sizes (2GiB, 0.25%)",
			totalMemory: 2 * GiB,
			ratio:       0.0025,
			want: sizes{
				CTMapSizeTCP:      LimitTableAutoGlobalTCPMin,
				CTMapSizeAny:      LimitTableAutoGlobalAnyMin,
				NATMapSize:        LimitTableAutoNatGlobalMin,
				NeighMapSize:      LimitTableAutoNatGlobalMin,
				SockRevNatMapSize: LimitTableAutoSockRevNatMin,
			},
		},
		{
			name:        "dynamic size without any static sizes (7.5GiB, 0.25%)",
			totalMemory: 7.5 * GiB,
			ratio:       0.0025,
			want: sizes{
				CTMapSizeTCP:      LimitTableAutoGlobalTCPMin,
				CTMapSizeAny:      LimitTableAutoGlobalAnyMin,
				NATMapSize:        LimitTableAutoNatGlobalMin,
				NeighMapSize:      LimitTableAutoNatGlobalMin,
				SockRevNatMapSize: LimitTableAutoSockRevNatMin,
			},
		},
		{
			name:        "dynamic size without any static sizes (16GiB, 0.25%)",
			totalMemory: 16 * GiB,
			ratio:       0.0025,
			want: sizes{
				CTMapSizeTCP:      151765,
				CTMapSizeAny:      75882,
				NATMapSize:        151765,
				NeighMapSize:      151765,
				SockRevNatMapSize: 75882,
			},
		},
		{
			name:        "dynamic size without any static sizes (120GiB, 0.25%)",
			totalMemory: 30 * GiB,
			ratio:       0.0025,
			want: sizes{
				CTMapSizeTCP:      284560,
				CTMapSizeAny:      142280,
				NATMapSize:        284560,
				NeighMapSize:      284560,
				SockRevNatMapSize: 142280,
			},
		},
		{
			name:        "dynamic size without any static sizes (240GiB, 0.25%)",
			totalMemory: 240 * GiB,
			ratio:       0.0025,
			want: sizes{
				CTMapSizeTCP:      2276484,
				CTMapSizeAny:      1138242,
				NATMapSize:        2276484,
				NeighMapSize:      2276484,
				SockRevNatMapSize: 1138242,
			},
		},
		{
			name:        "dynamic size without any static sizes (360GiB, 0.25%)",
			totalMemory: 360 * GiB,
			ratio:       0.0025,
			want: sizes{
				CTMapSizeTCP:      3414726,
				CTMapSizeAny:      1707363,
				NATMapSize:        3414726,
				NeighMapSize:      3414726,
				SockRevNatMapSize: 1707363,
			},
		},
		{
			name:        "dynamic size with static CT TCP size (4GiB, 0.25%)",
			totalMemory: 4 * GiB,
			ratio:       0.0025,
			want: sizes{
				CTMapSizeTCP:      CTMapEntriesGlobalTCPDefault + 1024,
				CTMapSizeAny:      65536,
				NATMapSize:        131072,
				NeighMapSize:      131072,
				SockRevNatMapSize: 65536,
			},
			preTestRun: func() {
				viper.Set(CTMapEntriesGlobalTCPName, CTMapEntriesGlobalTCPDefault+1024)
			},
		},
		{
			name:        "huge dynamic size ratio gets clamped (8GiB, 98%)",
			totalMemory: 16 * GiB,
			ratio:       0.98,
			want: sizes{
				CTMapSizeTCP:      LimitTableMax,
				CTMapSizeAny:      LimitTableMax,
				NATMapSize:        LimitTableMax,
				NeighMapSize:      LimitTableMax,
				SockRevNatMapSize: LimitTableMax,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			viper.Reset()

			if tt.preTestRun != nil {
				tt.preTestRun()
			}

			d := &DaemonConfig{
				CTMapEntriesGlobalTCP: viper.GetInt(CTMapEntriesGlobalTCPName),
				CTMapEntriesGlobalAny: viper.GetInt(CTMapEntriesGlobalAnyName),
				NATMapEntriesGlobal:   viper.GetInt(NATMapEntriesGlobalName),
				NeighMapEntriesGlobal: viper.GetInt(NeighMapEntriesGlobalName),
				SockRevNatEntries:     viper.GetInt(SockRevNatEntriesName),
			}

			// cannot set these from the Sizeof* consts from
			// pkg/maps/* due to circular dependencies.
			d.SetMapElementSizes(
				94, // ctmap.SizeofCTKey + policymap.SizeofCTEntry
				94, // nat.SizeofNATKey + nat.SizeofNATEntry
				24, // neighborsmap.SizeofNeighKey6 + neighborsmap.SizeOfNeighValue
				48, // lbmap.SizeofSockRevNat6Key+lbmap.SizeofSockRevNat6Value
			)

			if tt.totalMemory > 0 && tt.ratio > 0.0 {
				d.calculateDynamicBPFMapSizes(tt.totalMemory, tt.ratio)
			}

			got := sizes{
				d.CTMapEntriesGlobalTCP,
				d.CTMapEntriesGlobalAny,
				d.NATMapEntriesGlobal,
				d.NeighMapEntriesGlobal,
				d.SockRevNatEntries,
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("DaemonConfig.calculateDynamicBPFMapSize (-want +got):\n%s", diff)
			}
		})
	}
}
