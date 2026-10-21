// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn/bootstrap"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/mtu/fake"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

type restorePublisher struct {
	endpointmanager.EndpointManager
	published []*endpoint.Endpoint
}

func (p *restorePublisher) RestoreEndpoint(ep *endpoint.Endpoint) error {
	p.published = append(p.published, ep)
	// Stop at publication so no endpoint regeneration setup is needed.
	return errors.New("endpoint removed")
}

func TestEndpointRestoreInitialization(t *testing.T) {
	original := option.Config.RestoreState
	t.Cleanup(func() { option.Config.RestoreState = original })
	startupErr := errors.New("DNS proxy startup failed")
	for _, tt := range []struct {
		name         string
		restoreState bool
		wantErr      error
		wantHealth   string
	}{
		{name: "restoration enabled", restoreState: true, wantHealth: "Regenerating restored endpoints"},
		{name: "restoration disabled", wantHealth: "Skipped - state restore is disabled"},
		{name: "restoration enabled canceled", restoreState: true, wantErr: context.Canceled, wantHealth: "Waiting for K8s initialization"},
		{name: "restoration disabled canceled", wantErr: context.Canceled, wantHealth: "Waiting for K8s initialization"},
		{name: "restoration enabled DNS failed", restoreState: true, wantErr: startupErr, wantHealth: "Waiting for DNS proxy initialization"},
		{name: "restoration disabled DNS failed", wantErr: startupErr, wantHealth: "Waiting for DNS proxy initialization"},
		{name: "restoration enabled DNS canceled", restoreState: true, wantErr: context.Canceled, wantHealth: "Waiting for DNS proxy initialization"},
		{name: "restoration disabled DNS canceled", wantErr: context.Canceled, wantHealth: "Waiting for DNS proxy initialization"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.RestoreState = tt.restoreState
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			log := hivetest.Logger(t)
			ipc := ipcache.NewIPCache(&ipcache.Configuration{Context: ctx, Logger: log})
			t.Cleanup(func() { require.NoError(t, ipc.Shutdown()) })
			cacheReady := make(chan struct{})
			dirReady := &sync.WaitGroup{}
			dirReady.Add(1)
			releaseDir := sync.OnceFunc(dirReady.Done)
			lc := &cell.DefaultLifecycle{}
			apiFence := hive.NewFence(lc, log)
			require.NoError(t, lc.Start(log, ctx))
			t.Cleanup(func() { require.NoError(t, lc.Stop(log, context.Background())) })
			resolver, dnsProxyPromise := promise.New[bootstrap.DNSProxyInitialized]()
			publisher := &restorePublisher{}
			ep := &endpoint.Endpoint{ID: 123}
			r := &endpointRestorer{
				logger:                        log,
				endpointManager:               publisher,
				endpointAPIFence:              apiFence,
				cacheStatus:                   cacheReady,
				dirReadStatus:                 dirReady,
				ipCache:                       ipc,
				dnsProxyPromise:               dnsProxyPromise,
				restoreState:                  &endpointRestoreState{},
				metrics:                       newEndpointRestoreMetrics(),
				endpointRestoreComplete:       make(chan struct{}),
				endpointRegenerateComplete:    make(chan struct{}),
				endpointInitialPolicyComplete: make(chan struct{}),
			}
			if tt.restoreState {
				r.restoreState.restored = []*endpoint.Endpoint{ep}
			}
			waiters := []func(context.Context) error{
				r.WaitForEndpointRestoreWithoutRegeneration,
				r.WaitForEndpointRestore,
				r.WaitForInitialPolicy,
			}
			health, healthState := cell.NewSimpleHealth()
			done := make(chan error, 1)
			go func() {
				defer close(done)
				done <- r.InitRestore(ctx, health)
			}()
			t.Cleanup(func() { cancel(); releaseDir(); <-done })
			for _, step := range []struct {
				status  string
				unblock func()
			}{
				{"Waiting for K8s initialization", func() { close(cacheReady) }},
				{"Waiting for directory watcher to ingest policies from files", releaseDir},
				{"Waiting for initial IPCache revision", ipc.TriggerLabelInjection},
				{"Waiting for DNS proxy initialization", func() {
					if errors.Is(tt.wantErr, startupErr) {
						resolver.Reject(startupErr)
					} else {
						resolver.Resolve(bootstrap.DNSProxyInitialized{})
					}
				}},
			} {
				require.EventuallyWithT(t, func(c *assert.CollectT) {
					healthState.Lock()
					defer healthState.Unlock()
					assert.Equal(c, cell.StatusOK, healthState.Level)
					assert.Equal(c, step.status, healthState.Status)
					assert.NoError(c, healthState.Error)
				}, time.Second, time.Millisecond)
				for _, wait := range waiters {
					waitCtx, stop := context.WithTimeout(ctx, time.Millisecond)
					err := wait(waitCtx)
					stop()
					require.ErrorIs(t, err, context.DeadlineExceeded, "endpoint startup barriers must wait for initialization")
				}
				require.Empty(t, publisher.published, "restored endpoints must not be exposed before initialization")
				if errors.Is(tt.wantErr, context.Canceled) && step.status == tt.wantHealth {
					cancel()
					break
				}
				step.unblock()
			}
			require.ErrorIs(t, <-done, tt.wantErr)
			require.Equal(t, cell.StatusOK, healthState.Level)
			require.Equal(t, tt.wantHealth, healthState.Status)
			require.NoError(t, healthState.Error)
			if tt.wantErr == nil && tt.restoreState {
				require.Equal(t, []*endpoint.Endpoint{ep}, publisher.published)
			} else {
				require.Empty(t, publisher.published)
			}
			if tt.wantErr != nil {
				cancel()
			}
			wantWaitErr := ctx.Err()
			for _, wait := range waiters {
				require.ErrorIs(t, wait(ctx), wantWaitErr)
			}
		})
	}
}

func TestPrivilegedRemoveStaleEPIfaces(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		linkAttrs := netlink.NewLinkAttrs()
		linkAttrs.Name = "lxc12345"
		veth := &netlink.Veth{
			LinkAttrs: linkAttrs,
			PeerName:  "tmp54321",
		}

		err := netlink.LinkAdd(veth)
		assert.NoError(t, err)

		_, err = safenetlink.LinkByName(linkAttrs.Name)
		assert.NoError(t, err)

		restorer := &endpointRestorer{logger: hivetest.Logger(t)}
		err = restorer.clearStaleCiliumEndpointVeths()
		assert.NoError(t, err)

		// Check that stale iface is removed
		_, err = safenetlink.LinkByName(linkAttrs.Name)
		assert.Error(t, err)

		return nil
	})
}

func TestNeedsEndpointRoutingOnHost(t *testing.T) {
	oldIPAM := option.Config.IPAM
	oldInstallUplinkRoutes := option.Config.InstallUplinkRoutesForDelegatedIPAM
	defer func() {
		option.Config.IPAM = oldIPAM
		option.Config.InstallUplinkRoutesForDelegatedIPAM = oldInstallUplinkRoutes
	}()

	tests := []struct {
		name                                string
		ipam                                string
		installUplinkRoutesForDelegatedIPAM bool
		want                                bool
	}{
		{
			name: "ENI IPAM",
			ipam: ipamOption.IPAMENI,
			want: true,
		},
		{
			name: "Azure IPAM",
			ipam: ipamOption.IPAMAzure,
			want: true,
		},
		{
			name: "AlibabaCloud IPAM",
			ipam: ipamOption.IPAMAlibabaCloud,
			want: true,
		},
		{
			name: "cluster pool CIDR IPAM",
			ipam: ipamOption.IPAMKubernetes,
			want: false,
		},
		{
			name: "CRD IPAM",
			ipam: ipamOption.IPAMCRD,
			want: false,
		},
		{
			name:                                "delegated plugin without uplink routes",
			ipam:                                ipamOption.IPAMDelegatedPlugin,
			installUplinkRoutesForDelegatedIPAM: false,
			want:                                false,
		},
		{
			name:                                "delegated plugin with uplink routes",
			ipam:                                ipamOption.IPAMDelegatedPlugin,
			installUplinkRoutesForDelegatedIPAM: true,
			want:                                true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.IPAM = tt.ipam
			option.Config.InstallUplinkRoutesForDelegatedIPAM = tt.installUplinkRoutesForDelegatedIPAM

			r := &endpointRestorer{}
			require.Equal(t, tt.want, r.needsEndpointRoutingOnHost())
		})
	}
}

// TestPrivilegedConfigureRoutingInfoOnRestore verifies that configureRoutingInfo,
// called during endpoint restore, reconciles the egress ip rules of a restored
// endpoint to match the *current* masquerade configuration, even though those
// rules were originally installed once by CNI ADD under a potentially
// different configuration.
func TestPrivilegedConfigureRoutingInfoOnRestore(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		fakeMAC := "00:11:22:33:44:66"
		dummy := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name:         "epres-test",
				HardwareAddr: net.HardwareAddr(mac.MustParseMAC(fakeMAC)),
			},
		}
		require.NoError(t, netlink.LinkAdd(dummy))
		defer func() {
			require.NoError(t, netlink.LinkDel(dummy))
		}()

		oldIPAM := option.Config.IPAM
		oldMasq := option.Config.EnableIPv4Masquerade
		defer func() {
			option.Config.IPAM = oldIPAM
			option.Config.EnableIPv4Masquerade = oldMasq
		}()
		option.Config.IPAM = ipamOption.IPAMENI

		result := &ipam.AllocationResult{
			IP: netip.MustParseAddr("192.168.2.123"),
			CIDRs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/16"),
				netip.MustParsePrefix("192.170.0.0/16"),
			},
			PrimaryMAC:      fakeMAC,
			GatewayIP:       netip.MustParseAddr("192.168.2.1"),
			InterfaceNumber: "1",
		}

		restorer := &endpointRestorer{
			logger:     hivetest.Logger(t),
			mtuManager: &fake.MTU{},
		}

		// The endpoint was originally created (CNI ADD) while masquerading
		// was disabled, so an unconditional/catch-all egress rule is in place.
		option.Config.EnableIPv4Masquerade = false
		require.NoError(t, restorer.configureRoutingInfo(result))
		rules, err := safenetlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		catchAll, cidrSpecific := countEgressRulesForIP(rules, result.IP)
		require.Equal(t, 1, catchAll, "expected a single catch-all egress rule")
		require.Zero(t, cidrSpecific, "expected no CIDR-specific egress rules")

		// The datapath is reconfigured with masquerading enabled before the
		// agent restarts and endpoints are restored. The restore path must
		// reconcile the stale catch-all rule into per-CIDR rules.
		option.Config.EnableIPv4Masquerade = true
		require.NoError(t, restorer.configureRoutingInfo(result))
		rules, err = safenetlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		catchAll, cidrSpecific = countEgressRulesForIP(rules, result.IP)
		require.Zero(t, catchAll, "stale catch-all egress rule should have been removed")
		require.Equal(t, len(result.CIDRs), cidrSpecific, "expected one egress rule per CIDR")

		// The datapath is reconfigured again with masquerading disabled
		// before the next restart. The restore path must reconcile the
		// stale per-CIDR rules back into a single catch-all rule.
		option.Config.EnableIPv4Masquerade = false
		require.NoError(t, restorer.configureRoutingInfo(result))
		rules, err = safenetlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		catchAll, cidrSpecific = countEgressRulesForIP(rules, result.IP)
		require.Equal(t, 1, catchAll, "expected a single catch-all egress rule")
		require.Zero(t, cidrSpecific, "stale CIDR-specific egress rules should have been removed")

		require.NoError(t, linuxrouting.Delete(hivetest.Logger(t), result.IP))
		return nil
	})
}

// countEgressRulesForIP returns the number of catch-all (no 'to' field) and
// CIDR-specific ('to' field set) egress rules configured for the given
// source IP.
func countEgressRulesForIP(rules []netlink.Rule, ip netip.Addr) (catchAll, cidrSpecific int) {
	for _, rule := range rules {
		if rule.Src == nil || !rule.Src.IP.Equal(ip.AsSlice()) {
			continue
		}
		if rule.Dst == nil {
			catchAll++
		} else {
			cidrSpecific++
		}
	}
	return catchAll, cidrSpecific
}
