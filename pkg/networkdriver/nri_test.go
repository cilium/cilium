// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package networkdriver

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/containerd/nri/pkg/api"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"
	"golang.org/x/sys/unix"
	kubetypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/networkdriver/dummy"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/testutils"
	testnetns "github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPrivilegedRunStopPodSandbox(t *testing.T) {
	testutils.PrivilegedTest(t)

	const (
		rootNSName = "nri-root"
		podNSName  = "nri-pod"
		deviceName = "dummy0"
		podIfName  = "net1"
	)

	var (
		podUID   = kubetypes.UID("bbbbbbbb-0000-0000-0000-000000000002")
		claimUID = kubetypes.UID("aaaaaaaa-0000-0000-0000-000000000001")
		ipv4Addr = netip.MustParsePrefix("10.10.0.1/24")
		routes   = []types.Route{
			{
				Destination: netip.MustParsePrefix("10.10.0.128/28"),
				Gateway:     netip.MustParseAddr("10.10.0.128"),
			},
			{
				Destination: netip.MustParsePrefix("10.10.0.144/28"),
			},
		}
	)

	rootNS := testnetns.NewNetNS(t)
	podNS := testnetns.NewNetNS(t)

	pinDir := t.TempDir()
	rootNSPath := filepath.Join(pinDir, rootNSName)
	podNSPath := filepath.Join(pinDir, podNSName)
	pinNetNS(t, rootNS, rootNSPath)
	pinNetNS(t, podNS, podNSPath)

	origPodNetNSPath := podNetNSPath
	origRootNetNSPath := rootNetNSPath
	t.Cleanup(func() {
		podNetNSPath = origPodNetNSPath
		rootNetNSPath = origRootNetNSPath
	})
	podNetNSPath = pinDir
	rootNetNSPath = rootNSPath

	require.NoError(t, rootNS.Do(func() error {
		return netlink.LinkAdd(&netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{Name: deviceName},
		})
	}))

	driver := &Driver{
		logger: hivetest.Logger(t),
		allocations: map[kubetypes.UID]map[kubetypes.UID][]allocation{
			podUID: {
				claimUID: {
					{
						Device: &dummy.DummyDevice{Name: deviceName},
						Config: types.DeviceConfig{
							IPv4Addr:  ipv4Addr,
							PodIfName: podIfName,
							Routes:    routes,
						},
						Manager: types.DeviceManagerTypeDummy,
					},
				},
			},
		},
		ipv4Enabled: true,
	}
	podSandbox := &api.PodSandbox{
		Name:      "test-pod",
		Uid:       string(podUID),
		Namespace: "default",
		Linux: &api.LinuxPodSandbox{
			Namespaces: []*api.LinuxNamespace{
				{
					Type: "network",
					Path: podNSPath,
				},
			},
		},
	}

	require.NoError(t, rootNS.Do(func() error {
		return driver.RunPodSandbox(t.Context(), podSandbox)
	}))

	require.NoError(t, rootNS.Do(func() error {
		if _, err := safenetlink.LinkByName(deviceName); err == nil {
			return fmt.Errorf("expected %q to be moved out of root netns", deviceName)
		}
		return nil
	}))

	require.NoError(t, podNS.Do(func() error {
		if _, err := safenetlink.LinkByName(deviceName); err == nil {
			return fmt.Errorf("expected %q to be renamed in pod netns", deviceName)
		}

		link, err := safenetlink.LinkByName(podIfName)
		if err != nil {
			return fmt.Errorf("expected %q to be moved into pod netns", podIfName)
		}

		if link.Attrs().Flags&net.FlagUp == 0 {
			return fmt.Errorf("expected %q to be up", podIfName)
		}

		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return fmt.Errorf("failed to list %q addresses", podIfName)
		}
		if found := slices.ContainsFunc(addrs, func(addr netlink.Addr) bool {
			prefix, ok := netipx.FromStdIPNet(addr.IPNet)
			if !ok {
				return false
			}
			return ipv4Addr.Compare(prefix) == 0
		}); !found {
			return fmt.Errorf("expected address %q to be assigned to %q interface", ipv4Addr, podIfName)
		}

		nlRoutes, err := safenetlink.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       netipx.PrefixIPNet(routes[0].Destination),
				Gw:        routes[0].Gateway.AsSlice(),
			},
			netlink.RT_FILTER_OIF|netlink.RT_FILTER_DST|netlink.RT_FILTER_GW,
		)
		if err != nil {
			return fmt.Errorf("failed to list routes for %q", podIfName)
		}
		if len(nlRoutes) != 1 {
			return fmt.Errorf("no route \"%s via %s dev %s\" found", routes[0].Destination, routes[0].Gateway, podIfName)
		}

		nlRoutes, err = safenetlink.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       netipx.PrefixIPNet(routes[1].Destination),
			},
			netlink.RT_FILTER_OIF|netlink.RT_FILTER_DST,
		)
		if err != nil {
			return fmt.Errorf("failed to list routes for %q", podIfName)
		}
		if len(nlRoutes) != 1 {
			return fmt.Errorf("no route \"%s dev %s\" found", routes[1].Destination, podIfName)
		}

		return nil
	}))

	require.NoError(t, rootNS.Do(func() error {
		return driver.StopPodSandbox(t.Context(), podSandbox)
	}))

	require.NoError(t, podNS.Do(func() error {
		if _, err := safenetlink.LinkByName(podIfName); err == nil {
			return fmt.Errorf("expected %q to be moved out of pod netns", podIfName)
		}
		return nil
	}))

	require.NoError(t, rootNS.Do(func() error {
		if _, err := safenetlink.LinkByName(podIfName); err == nil {
			return fmt.Errorf("expected %q to be restored to %q in root netns", podIfName, deviceName)
		}

		link, err := safenetlink.LinkByName(deviceName)
		if err != nil {
			return err
		}

		if link.Attrs().Flags&net.FlagUp != 0 {
			return fmt.Errorf("expected %q to be down", deviceName)
		}

		addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return fmt.Errorf("failed to list %q addresses", deviceName)
		}
		if found := slices.ContainsFunc(addrs, func(addr netlink.Addr) bool {
			prefix, ok := netipx.FromStdIPNet(addr.IPNet)
			if !ok {
				return false
			}
			return ipv4Addr.Compare(prefix) == 0
		}); found {
			return fmt.Errorf("expected %q to have %s removed", deviceName, ipv4Addr)
		}

		nlRoutes, err := safenetlink.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				Dst: netipx.PrefixIPNet(routes[0].Destination),
				Gw:  routes[0].Gateway.AsSlice(),
			},
			netlink.RT_FILTER_DST|netlink.RT_FILTER_GW,
		)
		if err != nil {
			return fmt.Errorf("failed to list routes for destination %q", routes[0].Destination)
		}
		if len(nlRoutes) > 0 {
			return fmt.Errorf("expected no routes for destination %q", routes[0].Destination)
		}

		nlRoutes, err = safenetlink.RouteListFiltered(
			netlink.FAMILY_V4,
			&netlink.Route{
				Dst: netipx.PrefixIPNet(routes[1].Destination),
			},
			netlink.RT_FILTER_DST,
		)
		if err != nil {
			return fmt.Errorf("failed to list routes for destination %q", routes[1].Destination)
		}
		if len(nlRoutes) > 0 {
			return fmt.Errorf("expected no routes for destination %q", routes[1].Destination)
		}

		return nil
	}))
}

func pinNetNS(t *testing.T, ns *testnetns.NetNS, target string) {
	t.Helper()

	f, err := os.Create(target)
	require.NoError(t, err)
	require.NoError(t, f.Close())

	nsFDPath := fmt.Sprintf("/proc/self/fd/%d", ns.FD())
	require.NoError(t, unix.Mount(nsFDPath, target, "none", unix.MS_BIND, ""))
	t.Cleanup(func() {
		require.NoError(t, unix.Unmount(target, unix.MNT_DETACH))
		require.NoError(t, os.Remove(target))
	})
}
