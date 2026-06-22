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
	"github.com/cilium/cilium/pkg/networkdriver/macvlan"
	"github.com/cilium/cilium/pkg/networkdriver/sriov"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/testutils"
	testnetns "github.com/cilium/cilium/pkg/testutils/netns"
)

// TestPrivilegedRunStopPodSandbox exercises the NRI RunPodSandbox/StopPodSandbox device
// move-in/move-out flow, including the containerd < 2.1 fallback where StopPodSandbox is
// delivered with an empty namespace list (the sandbox task is killed before the NRI hook
// runs). Subtests:
//
//   - "run and stop with namespaces present": the happy path on containerd >= 2.1, where
//     both events carry the netns. Full assertions on addresses, routes and link state.
//   - "stop recovers netns from RunPodSandbox cache": containerd < 2.1; the netns was
//     cached while the task was alive at RunPodSandbox and recovered at StopPodSandbox.
//   - "stop recovers netns from Synchronize after restart": containerd < 2.1 across an
//     agent restart; the in-memory cache is lost and rebuilt from the NRI Synchronize
//     replay before the buggy StopPodSandbox arrives.
//
// sr-iov is used deliberately: macvlan and dummy are on-demand virtual devices that
// StopPodSandbox leaves in the pod netns to be reaped on netns deletion, so sr-iov is the
// only type that still travels back to root and exercises the rename/move-back/IP-and-route
// teardown path asserted below. The kernel link is a netlink.Dummy stand-in because a real
// VF cannot be created in a unit test; only the allocation's Manager (SRIOV) drives the
// code path under test.
func TestPrivilegedRunStopPodSandbox(t *testing.T) {
	testutils.PrivilegedTest(t)

	const (
		deviceName = "sriovvf0"
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

	// setup builds a fresh network scaffold and driver for a single subtest: a root and
	// a pod netns (pinned and wired into the package path globals), an sr-iov VF stand-in
	// (a netlink.Dummy, since a real VF cannot be created in a unit test) in the root
	// netns, and a Driver holding one allocation for that device. Returns the driver plus
	// the handles each subtest needs. All cleanup is registered on the subtest's t.
	setup := func(t *testing.T) (driver *Driver, rootNS, podNS *testnetns.NetNS, podNSPath string) {
		t.Helper()

		const (
			rootNSName = "nri-root"
			podNSName  = "nri-pod"
		)

		rootNS = testnetns.NewNetNS(t)
		podNS = testnetns.NewNetNS(t)

		pinDir := t.TempDir()
		rootNSPath := filepath.Join(pinDir, rootNSName)
		podNSPath = filepath.Join(pinDir, podNSName)
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

		driver = &Driver{
			logger: hivetest.Logger(t),
			allocations: map[kubetypes.UID]map[kubetypes.UID][]allocation{
				podUID: {
					claimUID: {
						{
							Device: &sriov.PciDevice{KernelIfaceName: deviceName},
							Config: types.DeviceConfig{
								IPv4Addr:  ipv4Addr,
								PodIfName: podIfName,
								Routes:    routes,
							},
							Manager: types.DeviceManagerTypeSRIOV,
						},
					},
				},
			},
			podNetns:    make(map[kubetypes.UID]string),
			ipv4Enabled: true,
		}

		return driver, rootNS, podNS, podNSPath
	}

	// liveSandbox is a PodSandbox whose sandbox task is still alive, so it carries the
	// network namespace — what RunPodSandbox and Synchronize see on every containerd.
	liveSandbox := func(podNSPath string) *api.PodSandbox {
		return &api.PodSandbox{
			Name:      "test-pod",
			Uid:       string(podUID),
			Namespace: "default",
			Linux: &api.LinuxPodSandbox{
				Namespaces: []*api.LinuxNamespace{
					{Type: "network", Path: podNSPath},
				},
			},
		}
	}

	// assertBuggyStopRecovers drives the containerd < 2.1 StopPodSandbox (empty namespace
	// list) against a driver whose cache has already been seeded, and asserts the device
	// is moved back to the root netns under its kernel name and the cache entry evicted.
	// It first checks the device is in the pod netns, so a no-op stop can't pass silently.
	assertBuggyStopRecovers := func(t *testing.T, driver *Driver, rootNS, podNS *testnetns.NetNS) {
		t.Helper()

		// Precondition: the device currently lives in the pod netns under its pod name.
		require.NoError(t, podNS.Do(func() error {
			if _, err := safenetlink.LinkByName(podIfName); err != nil {
				return fmt.Errorf("expected %q in pod netns before StopPodSandbox: %w", podIfName, err)
			}
			return nil
		}))

		// The bug: containerd < 2.1 delivers StopPodSandbox with no namespaces because the
		// sandbox task is already dead. The driver must fall back to its cache.
		buggyStopSandbox := &api.PodSandbox{
			Name:      "test-pod",
			Uid:       string(podUID),
			Namespace: "default",
			Linux:     &api.LinuxPodSandbox{}, // no namespaces, as buggy containerd sends
		}
		require.NoError(t, rootNS.Do(func() error {
			return driver.StopPodSandbox(t.Context(), buggyStopSandbox)
		}))

		// The device must be restored to the root netns under its kernel name despite the
		// missing netns in the stop event...
		require.NoError(t, rootNS.Do(func() error {
			if _, err := safenetlink.LinkByName(deviceName); err != nil {
				return fmt.Errorf("expected %q restored to root netns after StopPodSandbox: %w", deviceName, err)
			}
			return nil
		}))

		// ...and no longer be in the pod netns.
		require.NoError(t, podNS.Do(func() error {
			if _, err := safenetlink.LinkByName(podIfName); err == nil {
				return fmt.Errorf("expected %q to be moved out of pod netns", podIfName)
			}
			return nil
		}))

		// The cache entry must be evicted on the pod's terminal event.
		require.NotContains(t, driver.podNetns, podUID, "cache entry should be evicted after StopPodSandbox")
	}

	t.Run("run and stop with namespaces present", func(t *testing.T) {
		driver, rootNS, podNS, podNSPath := setup(t)

		podSandbox := liveSandbox(podNSPath)

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
	})

	t.Run("stop recovers netns from RunPodSandbox cache", func(t *testing.T) {
		driver, rootNS, podNS, podNSPath := setup(t)

		// Task alive: RunPodSandbox moves the device in and caches the netns.
		require.NoError(t, rootNS.Do(func() error {
			return driver.RunPodSandbox(t.Context(), liveSandbox(podNSPath))
		}))
		require.Equal(t, podNSPath, driver.podNetns[podUID],
			"RunPodSandbox should cache the pod netns while the task is alive")

		assertBuggyStopRecovers(t, driver, rootNS, podNS)
	})

	t.Run("stop recovers netns from Synchronize after restart", func(t *testing.T) {
		driver, rootNS, podNS, podNSPath := setup(t)

		// A previous agent instance moved the device into the pod netns.
		require.NoError(t, rootNS.Do(func() error {
			return driver.RunPodSandbox(t.Context(), liveSandbox(podNSPath))
		}))

		// The agent restarts: its in-memory pod→netns cache is lost.
		driver.podNetns = make(map[kubetypes.UID]string)

		// The NRI plugin reconnects and replays every running pod via Synchronize,
		// rebuilding the cache from the still-alive sandbox tasks.
		_, err := driver.Synchronize(t.Context(), []*api.PodSandbox{liveSandbox(podNSPath)}, nil)
		require.NoError(t, err)
		require.Equal(t, podNSPath, driver.podNetns[podUID],
			"Synchronize should rebuild the pod netns cache after a restart")

		assertBuggyStopRecovers(t, driver, rootNS, podNS)
	})
}

// TestPrivilegedRunPodSandboxRecreatesMissingDevice reproduces the post-reboot
// state: a macvlan allocation has been restored into driver.allocations, but the
// on-demand kernel link does not exist (the reboot reaped the pod netns and the
// link along with it, and the restore path does not call Device.Setup). The first
// RunPodSandbox after the reboot must re-create the link on demand and move it
// into the pod, instead of failing with "Link not found" and crash-looping the
// sandbox.
//
// macvlan is used deliberately: it is the only device type whose Setup creates a
// kernel link, so it is the only type that can reach this state.
func TestPrivilegedRunPodSandboxRecreatesMissingDevice(t *testing.T) {
	testutils.PrivilegedTest(t)

	const (
		rootNSName = "nri-recreate-root"
		podNSName  = "nri-recreate-pod"
		parentName = "nri-parent0"
		kernelName = "nri-parent0.7"
		podIfName  = "mvl0"
	)

	var (
		podUID   = kubetypes.UID("cccccccc-0000-0000-0000-000000000003")
		claimUID = kubetypes.UID("dddddddd-0000-0000-0000-000000000004")
		ipv4Addr = netip.MustParsePrefix("10.20.0.1/24")
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

	// Create only the macvlan parent in root. The macvlan sub-interface itself
	// is deliberately absent — this is the crux of the post-reboot bug.
	require.NoError(t, rootNS.Do(func() error {
		return netlink.LinkAdd(&netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{Name: parentName},
		})
	}))

	require.NoError(t, rootNS.Do(func() error {
		if _, err := safenetlink.LinkByName(kernelName); err == nil {
			return fmt.Errorf("precondition failed: %q must not exist before RunPodSandbox", kernelName)
		}
		return nil
	}))

	driver := &Driver{
		logger: hivetest.Logger(t),
		allocations: map[kubetypes.UID]map[kubetypes.UID][]allocation{
			podUID: {
				claimUID: {
					{
						Device: &macvlan.MacvlanDevice{
							Name:            "nri-parent0-7",
							ParentName:      parentName,
							KernelIfaceName: kernelName,
							Mode:            netlink.MACVLAN_MODE_BRIDGE,
						},
						Config: types.DeviceConfig{
							IPv4Addr:  ipv4Addr,
							PodIfName: podIfName,
						},
						Manager: types.DeviceManagerTypeMacvlan,
					},
				},
			},
		},
		podNetns:    make(map[kubetypes.UID]string),
		ipv4Enabled: true,
	}
	podSandbox := &api.PodSandbox{
		Name:      "test-recreate-pod",
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

	// RunPodSandbox must NOT fail even though the kernel link is missing: it
	// re-creates it on demand via Device.Setup.
	require.NoError(t, rootNS.Do(func() error {
		return driver.RunPodSandbox(t.Context(), podSandbox)
	}))

	// The re-created link must end up in the pod netns under the pod-facing name.
	require.NoError(t, podNS.Do(func() error {
		link, err := safenetlink.LinkByName(podIfName)
		if err != nil {
			return fmt.Errorf("expected re-created %q to be present in pod netns: %w", podIfName, err)
		}
		if _, ok := link.(*netlink.Macvlan); !ok {
			return fmt.Errorf("expected %q to be a macvlan, got %T", podIfName, link)
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
			return fmt.Errorf("expected address %q to be assigned to %q", ipv4Addr, podIfName)
		}

		return nil
	}))

	// Nothing must be left behind in root: the on-demand link lives only in the
	// pod, exactly as it would after a healthy initial prepare.
	require.NoError(t, rootNS.Do(func() error {
		if _, err := safenetlink.LinkByName(kernelName); err == nil {
			return fmt.Errorf("expected %q not to remain in root netns", kernelName)
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
