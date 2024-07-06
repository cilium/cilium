// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/lock"
)

func TestValidateIPv6ClusterAllocCIDR(t *testing.T) {
	valid1 := &DaemonConfig{
		ConfigPatchMutex:     new(lock.RWMutex),
		IPv6ClusterAllocCIDR: "fdfd::/64",
	}

	require.Nil(t, valid1.validateIPv6ClusterAllocCIDR())
	require.Equal(t, "fdfd::", valid1.IPv6ClusterAllocCIDRBase)

	valid2 := &DaemonConfig{
		ConfigPatchMutex:     new(lock.RWMutex),
		IPv6ClusterAllocCIDR: "fdfd:fdfd:fdfd:fdfd:aaaa::/64",
	}
	require.Nil(t, valid2.validateIPv6ClusterAllocCIDR())
	require.Equal(t, "fdfd:fdfd:fdfd:fdfd::", valid2.IPv6ClusterAllocCIDRBase)

	invalid1 := &DaemonConfig{
		ConfigPatchMutex:     new(lock.RWMutex),
		IPv6ClusterAllocCIDR: "foo",
	}
	require.NotNil(t, invalid1.validateIPv6ClusterAllocCIDR())

	invalid2 := &DaemonConfig{
		ConfigPatchMutex:     new(lock.RWMutex),
		IPv6ClusterAllocCIDR: "fdfd",
	}
	require.NotNil(t, invalid2.validateIPv6ClusterAllocCIDR())

	invalid3 := &DaemonConfig{
		ConfigPatchMutex:     new(lock.RWMutex),
		IPv6ClusterAllocCIDR: "fdfd::/32",
	}
	require.NotNil(t, invalid3.validateIPv6ClusterAllocCIDR())

	invalid4 := &DaemonConfig{
		ConfigPatchMutex: new(lock.RWMutex),
	}
	require.NotNil(t, invalid4.validateIPv6ClusterAllocCIDR())
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

func TestReadDirConfig(t *testing.T) {
	vp := viper.New()
	var dirName string
	type args struct {
		dirName string
	}
	type want struct {
		allSettings map[string]interface{}
		err         error
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
				dirName = t.TempDir()

				fs := flag.NewFlagSet("empty configuration", flag.ContinueOnError)
				vp.BindPFlags(fs)
			},
			setupArgs: func() args {
				return args{
					dirName: dirName,
				}
			},
			setupWant: func() want {
				return want{
					allSettings: map[string]interface{}{},
					err:         nil,
				}
			},
			postTestRun: func() {
				os.RemoveAll(dirName)
			},
		},
		{
			name: "single file configuration",
			preTestRun: func() {
				dirName = t.TempDir()

				fullPath := filepath.Join(dirName, "test")
				err := os.WriteFile(fullPath, []byte(`"1"
`), os.FileMode(0644))
				require.NoError(t, err)
				fs := flag.NewFlagSet("single file configuration", flag.ContinueOnError)
				fs.String("test", "", "")
				BindEnv(vp, "test")
				vp.BindPFlags(fs)

				fmt.Println(fullPath)
			},
			setupArgs: func() args {
				return args{
					dirName: dirName,
				}
			},
			setupWant: func() want {
				return want{
					allSettings: map[string]interface{}{"test": `"1"`},
					err:         nil,
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
		require.Equal(t, want.err, err, fmt.Sprintf("Test Name: %s", tt.name))
		err = MergeConfig(vp, m)
		require.NoError(t, err)
		assert.Equal(t, vp.AllSettings(), want.allSettings, fmt.Sprintf("Test Name: %s", tt.name))
		tt.postTestRun()
	}
}

func TestBindEnv(t *testing.T) {
	vp := viper.New()
	optName1 := "foo-bar"
	os.Setenv("LEGACY_FOO_BAR", "legacy")
	os.Setenv(getEnvName(optName1), "new")
	BindEnvWithLegacyEnvFallback(vp, optName1, "LEGACY_FOO_BAR")
	require.Equal(t, "new", vp.GetString(optName1))

	optName2 := "bar-foo"
	BindEnvWithLegacyEnvFallback(vp, optName2, "LEGACY_FOO_BAR")
	require.Equal(t, "legacy", vp.GetString(optName2))
}

func TestEnabledFunctions(t *testing.T) {
	d := &DaemonConfig{ConfigPatchMutex: new(lock.RWMutex)}
	assert.False(t, d.IPv4Enabled())
	assert.False(t, d.IPv6Enabled())
	assert.False(t, d.SCTPEnabled())
	d = &DaemonConfig{
		ConfigPatchMutex: new(lock.RWMutex),
		EnableIPv4:       true,
	}
	assert.True(t, d.IPv4Enabled())
	assert.False(t, d.IPv6Enabled())
	assert.False(t, d.SCTPEnabled())
	d = &DaemonConfig{
		ConfigPatchMutex: new(lock.RWMutex),
		EnableIPv6:       true,
	}
	assert.False(t, d.IPv4Enabled())
	assert.True(t, d.IPv6Enabled())
	assert.False(t, d.SCTPEnabled())
	d = &DaemonConfig{
		ConfigPatchMutex: new(lock.RWMutex),
		EnableSCTP:       true,
	}
	assert.False(t, d.IPv4Enabled())
	assert.False(t, d.IPv6Enabled())
	assert.True(t, d.SCTPEnabled())
	d = &DaemonConfig{
		ConfigPatchMutex: new(lock.RWMutex),
	}
	require.Empty(t, d.IPAMMode())
	d = &DaemonConfig{
		ConfigPatchMutex: new(lock.RWMutex),
		IPAM:             ipamOption.IPAMENI,
	}
	require.Equal(t, ipamOption.IPAMENI, d.IPAMMode())
}

func TestLocalAddressExclusion(t *testing.T) {
	d := &DaemonConfig{ConfigPatchMutex: new(lock.RWMutex)}
	err := d.parseExcludedLocalAddresses([]string{"1.1.1.1/32", "3.3.3.0/24", "f00d::1/128"})
	require.NoError(t, err)

	require.True(t, d.IsExcludedLocalAddress(net.ParseIP("1.1.1.1")))
	require.False(t, d.IsExcludedLocalAddress(net.ParseIP("1.1.1.2")))
	require.True(t, d.IsExcludedLocalAddress(net.ParseIP("3.3.3.1")))
	require.True(t, d.IsExcludedLocalAddress(net.ParseIP("f00d::1")))
	require.False(t, d.IsExcludedLocalAddress(net.ParseIP("f00d::2")))
}

func TestCheckMapSizeLimits(t *testing.T) {
	type sizes struct {
		AuthMapEntries        int
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
				ConfigPatchMutex:      new(lock.RWMutex),
				AuthMapEntries:        AuthMapEntriesDefault,
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
				AuthMapEntries:        AuthMapEntriesDefault,
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
				ConfigPatchMutex:      new(lock.RWMutex),
				AuthMapEntries:        20000,
				CTMapEntriesGlobalTCP: 20000,
				CTMapEntriesGlobalAny: 18000,
				NATMapEntriesGlobal:   2048,
				PolicyMapEntries:      512,
				LBMapEntries:          1 << 14,
				SockRevNatEntries:     18000,
				FragmentsMapEntries:   2 << 14,
			},
			want: sizes{
				AuthMapEntries:        20000,
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
			name: "Auth map size below range",
			d: &DaemonConfig{
				ConfigPatchMutex: new(lock.RWMutex),
				AuthMapEntries:   AuthMapEntriesMin - 1,
			},
			want: sizes{
				AuthMapEntries: AuthMapEntriesMin - 1,
				WantErr:        true,
			},
		},
		{
			name: "Auth map size above range",
			d: &DaemonConfig{
				ConfigPatchMutex: new(lock.RWMutex),
				AuthMapEntries:   AuthMapEntriesMax + 1,
			},
			want: sizes{
				AuthMapEntries: AuthMapEntriesMax + 1,
				WantErr:        true,
			},
		},
		{
			name: "CT TCP map size below range",
			d: &DaemonConfig{
				ConfigPatchMutex:      new(lock.RWMutex),
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
				ConfigPatchMutex:      new(lock.RWMutex),
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
				ConfigPatchMutex:      new(lock.RWMutex),
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
				ConfigPatchMutex:      new(lock.RWMutex),
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
				ConfigPatchMutex:    new(lock.RWMutex),
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
				ConfigPatchMutex:    new(lock.RWMutex),
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
				ConfigPatchMutex:      new(lock.RWMutex),
				AuthMapEntries:        AuthMapEntriesDefault,
				CTMapEntriesGlobalTCP: 2048,
				CTMapEntriesGlobalAny: 4096,
				NATMapEntriesGlobal:   NATMapEntriesGlobalDefault,
				SockRevNatEntries:     4096,
				PolicyMapEntries:      16384,
				LBMapEntries:          65536,
				FragmentsMapEntries:   defaults.FragmentsMapEntries,
			},
			want: sizes{
				AuthMapEntries:        AuthMapEntriesDefault,
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
				ConfigPatchMutex:      new(lock.RWMutex),
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
				ConfigPatchMutex: new(lock.RWMutex),
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
				ConfigPatchMutex: new(lock.RWMutex),
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
				ConfigPatchMutex:    new(lock.RWMutex),
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
				ConfigPatchMutex:    new(lock.RWMutex),
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
				AuthMapEntries:        tt.d.AuthMapEntries,
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
				ConfigPatchMutex:      new(lock.RWMutex),
				EnableIPv4Masquerade:  true,
				EnableIPv6Masquerade:  true,
				RoutingMode:           RoutingModeNative,
				IPAM:                  ipamOption.IPAMAzure,
				IPv4NativeRoutingCIDR: cidr.MustParseCIDR("10.127.64.0/18"),
				EnableIPv4:            true,
			},
			wantErr: false,
		},
		{
			name: "without native routing cidr and no masquerade",
			d: &DaemonConfig{
				ConfigPatchMutex:     new(lock.RWMutex),
				EnableIPv4Masquerade: false,
				EnableIPv6Masquerade: false,
				RoutingMode:          RoutingModeNative,
				IPAM:                 ipamOption.IPAMAzure,
				EnableIPv4:           true,
			},
			wantErr: false,
		},
		{
			name: "without native routing cidr and tunnel enabled",
			d: &DaemonConfig{
				ConfigPatchMutex:     new(lock.RWMutex),
				EnableIPv4Masquerade: true,
				EnableIPv6Masquerade: true,
				RoutingMode:          RoutingModeTunnel,
				IPAM:                 ipamOption.IPAMAzure,
				EnableIPv4:           true,
			},
			wantErr: false,
		},
		{
			name: "without native routing cidr and tunnel disabled",
			d: &DaemonConfig{
				ConfigPatchMutex:     new(lock.RWMutex),
				EnableIPv4Masquerade: true,
				EnableIPv6Masquerade: true,
				RoutingMode:          RoutingModeNative,
				IPAM:                 ipamOption.IPAMENI,
				EnableIPv4:           true,
			},
			wantErr: false,
		},
		{
			name: "without native routing cidr and with masquerade and tunnel disabled and ipam not eni",
			d: &DaemonConfig{
				ConfigPatchMutex:     new(lock.RWMutex),
				EnableIPv4Masquerade: true,
				EnableIPv6Masquerade: true,
				RoutingMode:          RoutingModeNative,
				IPAM:                 ipamOption.IPAMAzure,
				EnableIPv4:           true,
			},
			wantErr: true,
		},
		{
			name: "without native routing cidr and tunnel disabled, but ipmasq-agent",
			d: &DaemonConfig{
				ConfigPatchMutex:     new(lock.RWMutex),
				EnableIPv4Masquerade: true,
				EnableIPv6Masquerade: true,
				RoutingMode:          RoutingModeNative,
				IPAM:                 ipamOption.IPAMKubernetes,
				EnableIPv4:           true,
				EnableIPMasqAgent:    true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.d.checkIPv4NativeRoutingCIDR()
			if tt.wantErr && err == nil {
				t.Error("expected error, but got nil")
			} else if !tt.wantErr && err != nil {
				t.Errorf("expected no error, but got %q", err)
			}
		})
	}

}

func TestCheckIPv6NativeRoutingCIDR(t *testing.T) {
	tests := []struct {
		name    string
		d       *DaemonConfig
		wantErr bool
	}{
		{
			name: "with native routing cidr",
			d: &DaemonConfig{
				ConfigPatchMutex:      new(lock.RWMutex),
				EnableIPv4Masquerade:  true,
				EnableIPv6Masquerade:  true,
				RoutingMode:           RoutingModeNative,
				IPv6NativeRoutingCIDR: cidr.MustParseCIDR("fd00::/120"),
				EnableIPv6:            true,
			},
			wantErr: false,
		},
		{
			name: "without native routing cidr and no masquerade",
			d: &DaemonConfig{
				ConfigPatchMutex:     new(lock.RWMutex),
				EnableIPv4Masquerade: false,
				EnableIPv6Masquerade: false,
				RoutingMode:          RoutingModeNative,
				EnableIPv6:           true,
			},
			wantErr: false,
		},
		{
			name: "without native routing cidr and tunnel enabled",
			d: &DaemonConfig{
				ConfigPatchMutex:     new(lock.RWMutex),
				EnableIPv4Masquerade: true,
				EnableIPv6Masquerade: true,
				RoutingMode:          RoutingModeTunnel,
				EnableIPv6:           true,
			},
			wantErr: false,
		},
		{
			name: "without native routing cidr and tunnel disabled",
			d: &DaemonConfig{
				ConfigPatchMutex:     new(lock.RWMutex),
				EnableIPv4Masquerade: true,
				EnableIPv6Masquerade: true,
				RoutingMode:          RoutingModeNative,
				EnableIPv6:           true,
			},
			wantErr: true,
		},
		{
			name: "without native routing cidr and tunnel disabled, but ipmasq-agent",
			d: &DaemonConfig{
				ConfigPatchMutex:     new(lock.RWMutex),
				EnableIPv4Masquerade: true,
				EnableIPv6Masquerade: true,
				RoutingMode:          RoutingModeNative,
				EnableIPv6:           true,
				EnableIPMasqAgent:    true,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.d.checkIPv6NativeRoutingCIDR()
			if tt.wantErr && err == nil {
				t.Error("expected error, but got nil")
			} else if !tt.wantErr && err != nil {
				t.Errorf("expected no error, but got %q", err)
			}
		})
	}

}

func TestCheckIPAMDelegatedPlugin(t *testing.T) {
	tests := []struct {
		name      string
		d         *DaemonConfig
		expectErr error
	}{
		{
			name: "IPAMDelegatedPlugin with local router IPv4 set and endpoint health checking disabled",
			d: &DaemonConfig{
				ConfigPatchMutex: new(lock.RWMutex),
				IPAM:             ipamOption.IPAMDelegatedPlugin,
				EnableIPv4:       true,
				LocalRouterIPv4:  "169.254.0.0",
			},
			expectErr: nil,
		},
		{
			name: "IPAMDelegatedPlugin with local router IPv6 set and endpoint health checking disabled",
			d: &DaemonConfig{
				ConfigPatchMutex: new(lock.RWMutex),
				IPAM:             ipamOption.IPAMDelegatedPlugin,
				EnableIPv6:       true,
				LocalRouterIPv6:  "fe80::1",
			},
			expectErr: nil,
		},
		{
			name: "IPAMDelegatedPlugin with health checking enabled",
			d: &DaemonConfig{
				ConfigPatchMutex:             new(lock.RWMutex),
				IPAM:                         ipamOption.IPAMDelegatedPlugin,
				EnableHealthChecking:         true,
				EnableEndpointHealthChecking: true,
			},
			expectErr: fmt.Errorf("--enable-endpoint-health-checking must be disabled with --ipam=delegated-plugin"),
		},
		{
			name: "IPAMDelegatedPlugin without local router IPv4",
			d: &DaemonConfig{
				ConfigPatchMutex: new(lock.RWMutex),
				IPAM:             ipamOption.IPAMDelegatedPlugin,
				EnableIPv4:       true,
			},
			expectErr: fmt.Errorf("--local-router-ipv4 must be provided when IPv4 is enabled with --ipam=delegated-plugin"),
		},
		{
			name: "IPAMDelegatedPlugin without local router IPv6",
			d: &DaemonConfig{
				ConfigPatchMutex: new(lock.RWMutex),
				IPAM:             ipamOption.IPAMDelegatedPlugin,
				EnableIPv6:       true,
			},
			expectErr: fmt.Errorf("--local-router-ipv6 must be provided when IPv6 is enabled with --ipam=delegated-plugin"),
		},
		{
			name: "IPAMDelegatedPlugin with envoy config enabled",
			d: &DaemonConfig{
				ConfigPatchMutex:  new(lock.RWMutex),
				IPAM:              ipamOption.IPAMDelegatedPlugin,
				EnableEnvoyConfig: true,
			},
			expectErr: fmt.Errorf("--enable-envoy-config must be disabled with --ipam=delegated-plugin"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.d.checkIPAMDelegatedPlugin()
			if tt.expectErr != nil && err == nil {
				t.Errorf("expected error but got none")
			} else if tt.expectErr == nil && err != nil {
				t.Errorf("expected no error but got %q", err)
			} else if tt.expectErr != nil && tt.expectErr.Error() != err.Error() {
				t.Errorf("expected error %q but got %q", tt.expectErr, err)
			}
		})
	}
}

func Test_populateNodePortRange(t *testing.T) {
	vp := viper.New()
	reset := func() { vp = viper.New() }
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
				vp.Set(NodePortRange, []string{"23", "24"})
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
				reset()

				fs := flag.NewFlagSet(NodePortRange, flag.ContinueOnError)
				fs.StringSlice(
					NodePortRange,
					[]string{
						fmt.Sprintf("%d", NodePortMinDefault),
						fmt.Sprintf("%d", NodePortMaxDefault),
					},
					"")

				BindEnv(vp, NodePortRange)
				vp.BindPFlags(fs)
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
				reset()
				vp.Set(NodePortRange, []string{"666", "555"})
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
				reset()
				vp.Set(NodePortRange, []string{"666", "666"})
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
				reset()
				vp.Set(NodePortRange, []string{"aaa", "0"})
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
				reset()
				vp.Set(NodePortRange, []string{"1024", "aaa"})
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
				reset()

				fs := flag.NewFlagSet(NodePortRange, flag.ContinueOnError)
				fs.StringSlice(
					NodePortRange,
					[]string{
						fmt.Sprintf("%d", NodePortMinDefault),
						fmt.Sprintf("%d", NodePortMaxDefault),
					},
					"")

				BindEnv(vp, NodePortRange)
				vp.BindPFlags(fs)

				vp.Set(NodePortRange, []string{"1024"})
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
				reset()

				fs := flag.NewFlagSet(NodePortRange, flag.ContinueOnError)
				fs.StringSlice(
					NodePortRange,
					[]string{}, // Explicitly has no defaults.
					"")

				BindEnv(vp, NodePortRange)
				vp.BindPFlags(fs)

				vp.Set(NodePortRange, []string{})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.preTestRun()

			d := &DaemonConfig{}
			err := d.populateNodePortRange(vp)

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

func TestGetDefaultMonitorQueueSize(t *testing.T) {
	require.Equal(t, 4*defaults.MonitorQueueSizePerCPU, getDefaultMonitorQueueSize(4))
	require.Equal(t, defaults.MonitorQueueSizePerCPUMaximum, getDefaultMonitorQueueSize(1000))
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
		preTestRun  func(*viper.Viper)
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
			preTestRun: func(vp *viper.Viper) {
				vp.Set(CTMapEntriesGlobalTCPName, CTMapEntriesGlobalTCPDefault)
				vp.Set(CTMapEntriesGlobalAnyName, CTMapEntriesGlobalAnyDefault)
				vp.Set(NATMapEntriesGlobalName, NATMapEntriesGlobalDefault)
				// Neigh table has the same number of entries as NAT Map has.
				vp.Set(NeighMapEntriesGlobalName, NATMapEntriesGlobalDefault)
				vp.Set(SockRevNatEntriesName, SockRevNATMapEntriesDefault)
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
			preTestRun: func(vp *viper.Viper) {
				vp.Set(CTMapEntriesGlobalTCPName, CTMapEntriesGlobalTCPDefault+128)
				vp.Set(CTMapEntriesGlobalAnyName, CTMapEntriesGlobalAnyDefault-64)
				vp.Set(NATMapEntriesGlobalName, NATMapEntriesGlobalDefault+256)
				// Neigh table has the same number of entries as NAT Map has.
				vp.Set(NeighMapEntriesGlobalName, NATMapEntriesGlobalDefault+256)
				vp.Set(SockRevNatEntriesName, SockRevNATMapEntriesDefault+256)
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
			preTestRun: func(vp *viper.Viper) {
				vp.Set(CTMapEntriesGlobalTCPName, CTMapEntriesGlobalTCPDefault+1024)
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
		{
			name:        "dynamic size NAT size above limit with static CT sizes (issue #13843)",
			totalMemory: 128 * GiB,
			ratio:       0.0025,
			want: sizes{
				CTMapSizeTCP:      524288,
				CTMapSizeAny:      262144,
				NATMapSize:        (524288 + 262144) * 2 / 3,
				NeighMapSize:      524288,
				SockRevNatMapSize: 607062,
			},
			preTestRun: func(vp *viper.Viper) {
				vp.Set(CTMapEntriesGlobalTCPName, 524288)
				vp.Set(CTMapEntriesGlobalAnyName, 262144)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vp := viper.New()
			if tt.preTestRun != nil {
				tt.preTestRun(vp)
			}

			d := &DaemonConfig{
				ConfigPatchMutex:      new(lock.RWMutex),
				CTMapEntriesGlobalTCP: vp.GetInt(CTMapEntriesGlobalTCPName),
				CTMapEntriesGlobalAny: vp.GetInt(CTMapEntriesGlobalAnyName),
				NATMapEntriesGlobal:   vp.GetInt(NATMapEntriesGlobalName),
				NeighMapEntriesGlobal: vp.GetInt(NeighMapEntriesGlobalName),
				SockRevNatEntries:     vp.GetInt(SockRevNatEntriesName),
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
				d.calculateDynamicBPFMapSizes(vp, tt.totalMemory, tt.ratio)
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

func Test_backupFiles(t *testing.T) {
	tempDir := t.TempDir()
	fileNames := []string{"test.json", "test-1.json", "test-2.json"}

	backupFiles(tempDir, fileNames)
	files, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	// No files should have been created
	require.Len(t, files, 0)

	_, err = os.Create(filepath.Join(tempDir, "test.json"))
	require.NoError(t, err)

	backupFiles(tempDir, fileNames)
	files, err = os.ReadDir(tempDir)
	require.NoError(t, err)
	require.Len(t, files, 1)
	require.Equal(t, "test-1.json", files[0].Name())

	backupFiles(tempDir, fileNames)
	files, err = os.ReadDir(tempDir)
	require.NoError(t, err)
	require.Len(t, files, 1)
	require.Equal(t, "test-2.json", files[0].Name())

	_, err = os.Create(filepath.Join(tempDir, "test.json"))
	require.NoError(t, err)

	backupFiles(tempDir, fileNames)
	files, err = os.ReadDir(tempDir)
	require.NoError(t, err)
	require.Len(t, files, 2)
	require.Equal(t, "test-1.json", files[0].Name())
	require.Equal(t, "test-2.json", files[1].Name())
}

func Test_parseEventBufferTupleString(t *testing.T) {
	assert := assert.New(t)
	c, err := ParseEventBufferTupleString("enabled,123,1h")
	assert.NoError(err)
	assert.True(c.Enabled)
	assert.Equal(123, c.MaxSize)
	assert.Equal(time.Hour, c.TTL)

	c, err = ParseEventBufferTupleString("disabled,123,1h")
	assert.NoError(err)
	assert.False(c.Enabled)
	assert.Equal(123, c.MaxSize)
	assert.Equal(time.Hour, c.TTL)

	c, err = ParseEventBufferTupleString("cat,123,1h")
	assert.Error(err)

	c, err = ParseEventBufferTupleString("enabled,xxx,1h")
	assert.Error(err)

	c, err = ParseEventBufferTupleString("enabled,123,x")
	assert.Error(err)
}

func TestDaemonConfig_validateContainerIPLocalReservedPorts(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "default",
			value:   "auto",
			wantErr: assert.NoError,
		},
		{
			name:    "empty",
			value:   "",
			wantErr: assert.NoError,
		},
		{
			name:    "single port",
			value:   "1000",
			wantErr: assert.NoError,
		},
		{
			name:    "single range",
			value:   "1000-2000",
			wantErr: assert.NoError,
		},
		{
			name:    "port list",
			value:   "1000,2000",
			wantErr: assert.NoError,
		},
		{
			name:    "port range list",
			value:   "1000-1001,2000-2002",
			wantErr: assert.NoError,
		},
		{
			name:    "mixed",
			value:   "1000,2000-2002,3000,4000-4004",
			wantErr: assert.NoError,
		},
		{
			name:    "trailing comma",
			value:   "1,2,3,",
			wantErr: assert.Error,
		},
		{
			name:    "leading comma",
			value:   ",1,2,3",
			wantErr: assert.Error,
		},
		{
			name:    "invalid range",
			value:   "-",
			wantErr: assert.Error,
		},
		{
			name:    "invalid range end",
			value:   "1000-",
			wantErr: assert.Error,
		},
		{
			name:    "invalid range start",
			value:   "-1000",
			wantErr: assert.Error,
		},
		{
			name:    "invalid port",
			value:   "foo",
			wantErr: assert.Error,
		},
		{
			name:    "too many commas",
			value:   "1000,,2000",
			wantErr: assert.Error,
		},
		{
			name:    "invalid second value",
			value:   "1000,-",
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &DaemonConfig{ContainerIPLocalReservedPorts: tt.value}
			tt.wantErr(t, c.validateContainerIPLocalReservedPorts(), "validateContainerIPLocalReservedPorts()")
		})
	}
}

func TestDaemonConfig_StoreInFile(t *testing.T) {
	err := Config.StoreInFile(".")
	assert.NoError(t, err)

	err = Config.ValidateUnchanged(context.Background())
	assert.NoError(t, err)

	// minor change
	Config.DryMode = true
	err = Config.ValidateUnchanged(context.Background())
	assert.Error(t, err)
	assert.ErrorContains(t, err, "Config differs:", "Should return a validation error")
	Config.DryMode = false

	// IntOptions changes are ignored
	assert.False(t, Config.Opts.IsEnabled("unit-test-key-only")) // make sure not used
	Config.Opts.SetBool("unit-test-key-only", true)
	err = Config.ValidateUnchanged(context.Background())
	assert.NoError(t, err)
	Config.Opts.Delete("unit-test-key-only")
}
