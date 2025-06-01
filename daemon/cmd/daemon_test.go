// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/api/v1/server"
	cnicell "github.com/cilium/cilium/daemon/cmd/cni"
	fakecni "github.com/cilium/cilium/daemon/cmd/cni/fake"
	"github.com/cilium/cilium/pkg/controller"
	fakeDatapath "github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/datapath/prefilter"
	endpointapi "github.com/cilium/cilium/pkg/endpoint/api"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/fqdn/defaultdns"
	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/policymap"
	"github.com/cilium/cilium/pkg/metrics"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/netlink"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyAPI "github.com/cilium/cilium/pkg/policy/api"
	policycell "github.com/cilium/cilium/pkg/policy/cell"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/safenetlink"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

type DaemonSuite struct {
	hive *hive.Hive
	log  *slog.Logger

	d *Daemon

	// oldPolicyEnabled is the policy enforcement mode that was set before the test,
	// as returned by policy.GetPolicyEnabled().
	oldPolicyEnabled string

	PolicyImporter     policycell.PolicyImporter
	envoyXdsServer     envoy.XDSServer
	dnsProxy           defaultdns.Proxy
	endpointAPIManager endpointapi.EndpointAPIManager
}

func setupTestDirectories() string {
	tempRunDir, err := os.MkdirTemp("", "cilium-test-run")
	if err != nil {
		panic("TempDir() failed.")
	}

	err = os.Mkdir(filepath.Join(tempRunDir, "globals"), 0777)
	if err != nil {
		panic("Mkdir failed")
	}

	socketDir := envoy.GetSocketDir(tempRunDir)
	err = os.MkdirAll(socketDir, 0700)
	if err != nil {
		panic("creating envoy socket directory failed")
	}

	return tempRunDir
}

func TestMain(m *testing.M) {
	if !testutils.IntegrationTests() {
		// Immediately run the test suite without manipulating the environment
		// if integration tests are not requested.
		os.Exit(m.Run())
	}

	time.Local = time.UTC

	os.Exit(m.Run())
}

func setupDaemonSuite(tb testing.TB) *DaemonSuite {
	testutils.IntegrationTest(tb)

	ds := &DaemonSuite{
		log: hivetest.Logger(tb),
	}
	ctx := context.Background()

	ds.oldPolicyEnabled = policy.GetPolicyEnabled()
	policy.SetPolicyEnabled(option.DefaultEnforcement)

	var daemonPromise promise.Promise[*Daemon]
	ds.hive = hive.New(
		cell.Provide(
			func(log *slog.Logger) k8sClient.Clientset {
				cs, _ := k8sClient.NewFakeClientset(log)
				cs.Disable()
				return cs
			},
			func() *option.DaemonConfig { return option.Config },
			func() cnicell.CNIConfigManager { return &fakecni.FakeCNIConfigManager{} },
			func() ctmap.GCRunner { return ctmap.NewFakeGCRunner() },
			func() policymap.Factory { return nil },
			k8sSynced.RejectedCRDSyncPromise,
			func() *loadbalancer.TestConfig {
				return &loadbalancer.TestConfig{}
			},
			func() *server.Server { return nil },
		),
		fakeDatapath.Cell,
		prefilter.Cell,
		monitorAgent.Cell,
		ControlPlane,
		metrics.Cell,
		store.Cell,
		defaultdns.Cell,
		cell.Invoke(func(p promise.Promise[*Daemon]) {
			daemonPromise = p
		}),
		cell.Invoke(func(pi policycell.PolicyImporter) {
			ds.PolicyImporter = pi
		}),
		cell.Invoke(func(envoyXdsServer envoy.XDSServer) {
			ds.envoyXdsServer = envoyXdsServer
		}),
		cell.Invoke(func(dnsProxy defaultdns.Proxy) {
			ds.dnsProxy = dnsProxy
		}),
		cell.Invoke(func(endpointAPIManager endpointapi.EndpointAPIManager) {
			ds.endpointAPIManager = endpointAPIManager
		}),
	)

	// bootstrap global config
	ds.setupConfigOptions()

	// create temporary test directories and update global config accordingly
	testRunDir := setupTestDirectories()
	option.Config.RunDir = testRunDir
	option.Config.StateDir = testRunDir

	err := ds.hive.Start(ds.log, ctx)
	require.NoError(tb, err)

	ds.d, err = daemonPromise.Await(ctx)
	require.NoError(tb, err)

	ds.dnsProxy.Set(fqdnproxy.MockFQDNProxy{})

	ds.d.policy.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())

	// Reset the most common endpoint states before each test.
	for _, s := range []string{
		string(models.EndpointStateReady),
		string(models.EndpointStateWaitingDashForDashIdentity),
		string(models.EndpointStateWaitingDashToDashRegenerate),
	} {
		metrics.EndpointStateCount.WithLabelValues(s).Set(0.0)
	}

	tb.Cleanup(func() {
		controller.NewManager().RemoveAllAndWait()

		// It's helpful to keep the directories around if a test failed; only delete
		// them if tests succeed.
		if !tb.Failed() {
			os.RemoveAll(option.Config.RunDir)
		}

		// Restore the policy enforcement mode.
		policy.SetPolicyEnabled(ds.oldPolicyEnabled)

		err := ds.hive.Stop(ds.log, ctx)
		require.NoError(tb, err)

		ds.d.Close()
	})

	return ds
}

func (ds *DaemonSuite) setupConfigOptions() {
	// Set up all configuration options which are global to the entire test
	// run.
	mockCmd := &cobra.Command{}
	ds.hive.RegisterFlags(mockCmd.Flags())
	InitGlobalFlags(ds.log, mockCmd, ds.hive.Viper())
	option.Config.Populate(ds.log, ds.hive.Viper())
	option.Config.IdentityAllocationMode = option.IdentityAllocationModeKVstore
	option.Config.DryMode = true
	option.Config.Opts = option.NewIntOptions(&option.DaemonMutableOptionLibrary)
	// GetConfig the default labels prefix filter
	err := labelsfilter.ParseLabelPrefixCfg(ds.log, nil, nil, "")
	if err != nil {
		panic("ParseLabelPrefixCfg() failed")
	}
	option.Config.Opts.SetBool(option.DropNotify, true)
	option.Config.Opts.SetBool(option.TraceNotify, true)
	option.Config.Opts.SetBool(option.PolicyVerdictNotify, true)

	// Disable the replacement, as its initialization function execs bpftool
	// which requires root privileges. This would require marking the test suite
	// as privileged.
	option.Config.KubeProxyReplacement = option.KubeProxyReplacementFalse
}

type DaemonEtcdSuite struct {
	DaemonSuite
}

func setupDaemonEtcdSuite(tb testing.TB) *DaemonEtcdSuite {
	testutils.IntegrationTest(tb)
	kvstore.SetupDummy(tb, "etcd")

	ds := setupDaemonSuite(tb)
	return &DaemonEtcdSuite{
		DaemonSuite: *ds,
	}
}

// convenience wrapper that adds a single policy
func (ds *DaemonSuite) policyImport(rules policyAPI.Rules) {
	ds.updatePolicy(&policyTypes.PolicyUpdate{
		Rules: rules,
	})
}

// convenience wrapper that synchronously performs a policy update
func (ds *DaemonSuite) updatePolicy(upd *policyTypes.PolicyUpdate) {
	dc := make(chan uint64, 1)
	upd.DoneChan = dc
	ds.PolicyImporter.UpdatePolicy(upd)
	<-dc
}

func TestRemoveOldRouterState(t *testing.T) {
	tests := []struct {
		name       string
		ipv6       bool
		restoredIP net.IP
		addrs      []netlink.Addr
		wantErr    bool
	}{
		{
			name:       "no stale IPs",
			ipv6:       false,
			restoredIP: net.ParseIP("192.168.1.1"),
			addrs: []netlink.Addr{
				{IPNet: &net.IPNet{IP: net.ParseIP("192.168.1.1"), Mask: net.CIDRMask(24, 32)}},
			},
			wantErr: false,
		},
		{
			name:       "has stale IPv4 IPs",
			ipv6:       false,
			restoredIP: net.ParseIP("192.168.1.1"),
			addrs: []netlink.Addr{
				{IPNet: &net.IPNet{IP: net.ParseIP("192.168.1.1"), Mask: net.CIDRMask(24, 32)}},
				{IPNet: &net.IPNet{IP: net.ParseIP("192.168.1.2"), Mask: net.CIDRMask(24, 32)}},
				{IPNet: &net.IPNet{IP: net.ParseIP("192.168.1.3"), Mask: net.CIDRMask(24, 32)}},
			},
			wantErr: false,
		},
		{
			name:       "has stale IPv6 IPs",
			ipv6:       true,
			restoredIP: net.ParseIP("2001:db8::1"),
			addrs: []netlink.Addr{
				{IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(64, 128)}},
				{IPNet: &net.IPNet{IP: net.ParseIP("2001:db8::2"), Mask: net.CIDRMask(64, 128)}},
			},
			wantErr: false,
		},
		{
			name:       "link not found",
			ipv6:       false,
			restoredIP: net.ParseIP("192.168.1.1"),
			addrs:      nil,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock netlink interface
			mockNetlink := &mockNetlinkHandler{
				link: &mockLink{
					addrs: tt.addrs,
				},
			}

			// Replace the real netlink handler with our mock
			oldNetlink := safenetlink.LinkByName
			safenetlink.LinkByName = mockNetlink.LinkByName
			defer func() { safenetlink.LinkByName = oldNetlink }()

			oldAddrList := safenetlink.AddrList
			safenetlink.AddrList = mockNetlink.AddrList
			defer func() { safenetlink.AddrList = oldAddrList }()

			oldAddrDel := netlink.AddrDel
			netlink.AddrDel = mockNetlink.AddrDel
			defer func() { netlink.AddrDel = oldAddrDel }()

			err := removeOldRouterState(slog.Default(), tt.ipv6, tt.restoredIP)
			if (err != nil) != tt.wantErr {
				t.Errorf("removeOldRouterState() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Verify that stale IPs were removed
			if mockNetlink.removedAddrs != nil {
				for _, addr := range tt.addrs {
					if !addr.IP.Equal(tt.restoredIP) {
						found := false
						for _, removed := range mockNetlink.removedAddrs {
							if removed.IP.Equal(addr.IP) {
								found = true
								break
							}
						}
						if !found {
							t.Errorf("stale IP %v was not removed", addr.IP)
						}
					}
				}
			}
		})
	}
}

// Mock implementations for testing
type mockLink struct {
	netlink.Link
	addrs []netlink.Addr
}

type mockNetlinkHandler struct {
	link         *mockLink
	removedAddrs []netlink.Addr
}

func (m *mockNetlinkHandler) LinkByName(name string) (netlink.Link, error) {
	if m.link == nil {
		return nil, &netlink.LinkNotFoundError{}
	}
	return m.link, nil
}

func (m *mockNetlinkHandler) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	if m.link == nil {
		return nil, nil
	}
	return m.link.addrs, nil
}

func (m *mockNetlinkHandler) AddrDel(link netlink.Link, addr *netlink.Addr) error {
	if m.removedAddrs == nil {
		m.removedAddrs = make([]netlink.Addr, 0)
	}
	m.removedAddrs = append(m.removedAddrs, *addr)
	return nil
}
