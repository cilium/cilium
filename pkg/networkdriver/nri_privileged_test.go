// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"bytes"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	kubetypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/testutils"
	testnetns "github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPrivilegedRunStopPodSandbox(t *testing.T) {
	testutils.PrivilegedTest(t)

	const (
		devName   = "test-dev0"
		podIfName = "net1"
		podUID    = kubetypes.UID("bbbbbbbb-0000-0000-0000-0000000000aa")
		claimUID  = kubetypes.UID("aaaaaaaa-0000-0000-0000-0000000000bb")
	)

	hostNs := testnetns.NewNetNS(t)
	podNs := testnetns.NewNetNS(t)

	origPodNetNSPath, origRootNetNSPath := podNetNSPath, rootNetNSPath
	podNetNSPath = "/proc/self/fd"
	rootNetNSPath = fmt.Sprintf("/proc/self/fd/%d", hostNs.FD())
	t.Cleanup(func() { podNetNSPath, rootNetNSPath = origPodNetNSPath, origRootNetNSPath })

	sandbox := podSandbox(string(podUID), fmt.Sprintf("/proc/self/fd/%d", podNs.FD()))

	route := func(dst, gw string) types.StaticRoute {
		r := types.StaticRoute{Destination: netip.MustParsePrefix(dst)}
		if gw != "" {
			gateway := netip.MustParseAddr(gw)
			r.Gateway = &gateway
		}
		return r
	}

	ipv6 := false
	require.NoError(t, hostNs.Do(func() error {
		b, err := os.ReadFile("/proc/sys/net/ipv6/conf/all/disable_ipv6")
		ipv6 = err == nil && strings.TrimSpace(string(b)) == "0"
		return nil
	}))

	config := types.DeviceConfig{PodIfName: podIfName, IPv4Addr: netip.MustParsePrefix("10.20.0.5/20")}
	routes := []types.StaticRoute{route("10.40.0.0/16", "10.20.0.1"), route("10.60.0.0/16", "")}
	wantAddrs := []string{"10.20.0.5/20"}
	wantRoutes4 := [][2]string{{"10.40.0.0/16", "10.20.0.1"}, {"10.60.0.0/16", ""}}
	var wantRoutes6 [][2]string
	if ipv6 {
		config.IPv6Addr = netip.MustParsePrefix("fd00:20::5/56")
		routes = append(routes, route("fd00:30::/48", "fd00:20::1"))
		wantAddrs = append(wantAddrs, "fd00:20::5/56")
		wantRoutes6 = [][2]string{{"fd00:30::/48", "fd00:20::1"}}
	}

	driver := buildNRIDriver(t)
	// StopPodSandbox only logs the cleanup failures
	var logs bytes.Buffer
	driver.logger = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn}))

	wtxn := driver.db.WriteTxn(driver.allocationTable)
	_, _, err := driver.allocationTable.Insert(wtxn, &DRAAllocation{
		DeviceName: devName,
		// StopPodSandbox does not clean up the devices of the dummy manager
		Manager:        types.DeviceManagerTypeMock,
		PreparedDevice: &trackedDevice{name: devName},
		StaticRoutes:   routes,
		PodUID:         podUID,
		ClaimUID:       claimUID,
		Config:         config,
	})
	require.NoError(t, err)
	wtxn.Commit()

	hasRoute := func(routes []netlink.Route, dst, gw string) bool {
		for _, r := range routes {
			if r.Dst == nil || r.Dst.String() != dst || int(r.Protocol) != unix.RTPROT_STATIC {
				continue
			}
			if gw == "" && len(r.Gw) == 0 || gw != "" && r.Gw.Equal(net.ParseIP(gw)) {
				return true
			}
		}
		return false
	}

	requireConfigured := func() {
		assert.NoError(t, podNs.Do(func() error {
			l, err := safenetlink.LinkByName(podIfName)
			if err != nil {
				return err
			}
			assert.NotZero(t, l.Attrs().Flags&net.FlagUp, "device should be up")

			addrs, err := safenetlink.AddrList(l, netlink.FAMILY_ALL)
			if err != nil {
				return err
			}
			var gotAddrs []string
			for _, addr := range addrs {
				if !addr.IP.IsLinkLocalUnicast() {
					gotAddrs = append(gotAddrs, addr.IPNet.String())
				}
			}
			assert.ElementsMatch(t, wantAddrs, gotAddrs)

			for _, family := range []struct {
				id   int
				want [][2]string
			}{{netlink.FAMILY_V4, wantRoutes4}, {netlink.FAMILY_V6, wantRoutes6}} {
				got, err := safenetlink.RouteList(l, family.id)
				if err != nil {
					return err
				}
				for _, want := range family.want {
					assert.True(t, hasRoute(got, want[0], want[1]), "missing route %v", want)
				}
			}
			return nil
		}))
	}

	requireNotInPodNetns := func(names ...string) {
		assert.NoError(t, podNs.Do(func() error {
			for _, name := range names {
				_, err := safenetlink.LinkByName(name)
				assert.ErrorAs(t, err, new(netlink.LinkNotFoundError), "%s should not be in the pod netns", name)
			}
			return nil
		}))
	}

	requireBackInRootNetns := func(name string) {
		l, err := safenetlink.LinkByName(name)
		if assert.NoError(t, err, "%s should be back in the root netns", name) {
			addrs, err := safenetlink.AddrList(l, netlink.FAMILY_ALL)
			assert.NoError(t, err)
			assert.Empty(t, addrs)
		}
	}

	// everything runs in hostNs: RunPodSandbox looks for the device in the netns of the caller
	require.NoError(t, hostNs.Do(func() error {
		if err := netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: devName}}); err != nil {
			return err
		}

		// the device is configured and then moved back without any cleanup failure
		if err := driver.RunPodSandbox(t.Context(), sandbox); err != nil {
			return err
		}
		requireConfigured()
		if err := driver.StopPodSandbox(t.Context(), sandbox); err != nil {
			return err
		}
		requireBackInRootNetns(devName)
		requireNotInPodNetns(podIfName, devName)
		assert.NotContains(t, logs.String(), "Failed to")

		// the device is not in the pod netns anymore
		logs.Reset()
		if err := driver.StopPodSandbox(t.Context(), sandbox); err != nil {
			return err
		}
		assert.Contains(t, logs.String(), "Failed to find device in the pod namespace")

		// a route is gone, the cleanup goes on
		if err := driver.RunPodSandbox(t.Context(), sandbox); err != nil {
			return err
		}
		requireConfigured()
		if err := podNs.Do(func() error {
			l, err := safenetlink.LinkByName(podIfName)
			if err != nil {
				return err
			}
			_, dst, err := net.ParseCIDR("10.40.0.0/16")
			if err != nil {
				return err
			}
			return netlink.RouteDel(&netlink.Route{LinkIndex: l.Attrs().Index, Dst: dst, Protocol: unix.RTPROT_STATIC})
		}); err != nil {
			return err
		}
		logs.Reset()
		if err := driver.StopPodSandbox(t.Context(), sandbox); err != nil {
			return err
		}
		requireBackInRootNetns(devName)
		requireNotInPodNetns(podIfName, devName)
		assert.Contains(t, logs.String(), "Failed to delete static routes")
		for _, msg := range []string{"Failed to delete addresses", "Failed to set device down", "Failed to move device"} {
			assert.NotContains(t, logs.String(), msg)
		}

		// the device cannot be renamed back, it is moved back anyway
		if err := driver.RunPodSandbox(t.Context(), sandbox); err != nil {
			return err
		}
		if err := podNs.Do(func() error {
			return netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: devName}})
		}); err != nil {
			return err
		}
		logs.Reset()
		if err := driver.StopPodSandbox(t.Context(), sandbox); err != nil {
			return err
		}
		assert.Contains(t, logs.String(), "failed to restore device name")
		requireBackInRootNetns(podIfName)
		requireNotInPodNetns(podIfName)
		return nil
	}))
}
