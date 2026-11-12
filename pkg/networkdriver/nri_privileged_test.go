// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package networkdriver

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/containerd/nri/pkg/api"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	kubetypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/networkdriver/types"
	"github.com/cilium/cilium/pkg/testutils"
)

// hostLinkDevice stands in for an sr-iov VF: a dummy link whose name may
// change, located by its alias (like a VF by its PCI address) instead.
type hostLinkDevice struct {
	*trackedDevice
	// alias identifies the link independently of its name, like a VF's PCI
	// address.
	alias string
}

func (d *hostLinkDevice) FindLink() (netlink.Link, error) {
	links, err := safenetlink.LinkList()
	if err != nil {
		return nil, err
	}
	for _, l := range links {
		if l.Attrs().Alias == d.alias {
			return l, nil
		}
	}
	return nil, fmt.Errorf("alias %s: %w", d.alias, types.ErrLinkNotFound)
}

// privNRIEnv is a driver with one prepared allocation for a device backed by
// a real link, plus a pod netns pinned under a temp podNetNSPath.
type privNRIEnv struct {
	driver  *Driver
	dev     *hostLinkDevice
	sandbox *api.PodSandbox
	podNs   *netns.NetNS
	claim   kubeletplugin.NamespacedObject
}

func setupPrivNRIEnv(t *testing.T) *privNRIEnv {
	return setupPrivNRIEnvIfName(t, "mydevice")
}

// setupPrivNRIEnvIfName is setupPrivNRIEnv with the claim's podIfName set to
// podIfName, or unset if empty.
func setupPrivNRIEnvIfName(t *testing.T, podIfName string) *privNRIEnv {
	t.Helper()
	testutils.PrivilegedTest(t)

	// Isolate the test from the host: the "root" netns is a fresh netns and
	// pod netns paths resolve under a temp dir.
	hostNs, err := netns.New()
	require.NoError(t, err)
	t.Cleanup(func() { hostNs.Close() })

	podNs, err := netns.New()
	require.NoError(t, err)
	t.Cleanup(func() { podNs.Close() })

	dir := t.TempDir()
	hostPin := filepath.Join(dir, "host")
	podPin := filepath.Join(dir, "pod")
	pinNetNS(t, hostNs, hostPin)
	pinNetNS(t, podNs, podPin)

	oldPod, oldRoot := podNetNSPath, rootNetNSPath
	podNetNSPath, rootNetNSPath = dir, hostPin
	t.Cleanup(func() { podNetNSPath, rootNetNSPath = oldPod, oldRoot })

	const kernelName = "vf0"
	require.NoError(t, hostNs.Do(func() error {
		l := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: kernelName}}
		if err := netlink.LinkAdd(l); err != nil {
			return err
		}
		// LinkAdd does not set the alias.
		return netlink.LinkSetAlias(l, "pci-0000:17:00.2")
	}))

	cs, _ := k8sClient.NewFakeClientset(hivetest.Logger(t))
	td := &trackedDevice{name: prepTestDev0, kernelIfName: kernelName}
	claim := buildPrepClaim(prepTestDev0)
	params := map[string]string{}
	if podIfName != "" {
		params["podIfName"] = podIfName
	}
	raw, err := json.Marshal(params)
	require.NoError(t, err)
	claim.Status.Allocation.Devices.Config[0].Opaque.Parameters.Raw = raw
	createPrepClaim(t, cs, claim)

	dev := &hostLinkDevice{trackedDevice: td, alias: "pci-0000:17:00.2"}
	td.prepared = dev
	td.recoverFunc = func(types.DeviceAllocation) (types.Device, error) {
		t.Error("Recover must not be called: the link exists on the host")
		return dev, nil
	}
	driver := buildPrepDriver(t, cs, td)
	driver.podNetns = map[kubetypes.UID]string{}
	require.NoError(t, prepOne(t, driver, claim).Err)

	sandbox := &api.PodSandbox{
		Uid: string(prepTestPodUID),
		Linux: &api.LinuxPodSandbox{
			Namespaces: []*api.LinuxNamespace{{Type: "network", Path: podPin}},
		},
	}

	return &privNRIEnv{
		driver:  driver,
		dev:     dev,
		sandbox: sandbox,
		podNs:   podNs,
		claim:   namedObject(prepTestClaimNS, prepTestClaimName, prepTestClaimUID),
	}
}

// pinNetNS bind-mounts ns at path, like the container runtime pins pod netns.
func pinNetNS(t *testing.T, ns *netns.NetNS, path string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, nil, 0o444))
	src := fmt.Sprintf("/proc/self/fd/%d", ns.FD())
	require.NoError(t, unix.Mount(src, path, "", unix.MS_BIND, ""))
	t.Cleanup(func() { unix.Unmount(path, unix.MNT_DETACH) })
}

func linkNames(t *testing.T, ns *netns.NetNS) []string {
	t.Helper()
	var names []string
	require.NoError(t, ns.Do(func() error {
		links, err := safenetlink.LinkList()
		for _, l := range links {
			if l.Attrs().Name != "lo" {
				names = append(names, l.Attrs().Name)
			}
		}
		return err
	}))
	return names
}

func TestPrivilegedStopPodSandboxRenamesBack(t *testing.T) {
	env := setupPrivNRIEnv(t)
	hostNs, err := netns.OpenPinned(rootNetNSPath)
	require.NoError(t, err)
	defer hostNs.Close()

	require.NoError(t, hostNs.Do(func() error {
		return env.driver.RunPodSandbox(t.Context(), env.sandbox)
	}))
	require.NoError(t, hostNs.Do(func() error {
		return env.driver.StopPodSandbox(t.Context(), env.sandbox)
	}))
	require.Empty(t, linkNames(t, env.podNs))
	require.Equal(t, []string{"vf0"}, linkNames(t, hostNs), "renamed back")
}

func TestPrivilegedStopPodSandboxRenameBackFails(t *testing.T) {
	env := setupPrivNRIEnv(t)
	hostNs, err := netns.OpenPinned(rootNetNSPath)
	require.NoError(t, err)
	defer hostNs.Close()

	require.NoError(t, hostNs.Do(func() error {
		return env.driver.RunPodSandbox(t.Context(), env.sandbox)
	}))
	// The kernel name is taken in the pod, so the rename back fails.
	require.NoError(t, env.podNs.Do(func() error {
		return netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "vf0"}})
	}))

	// The device is moved back anyway, under its pod-side name.
	require.NoError(t, hostNs.Do(func() error {
		return env.driver.StopPodSandbox(t.Context(), env.sandbox)
	}))
	require.Equal(t, []string{"vf0"}, linkNames(t, env.podNs))
	require.Equal(t, []string{"mydevice"}, linkNames(t, hostNs))
}

func TestPrivilegedStopPodSandboxNoPodIfName(t *testing.T) {
	env := setupPrivNRIEnvIfName(t, "")
	hostNs, err := netns.OpenPinned(rootNetNSPath)
	require.NoError(t, err)
	defer hostNs.Close()

	require.NoError(t, hostNs.Do(func() error {
		return env.driver.RunPodSandbox(t.Context(), env.sandbox)
	}))
	// Something in the pod renames the device.
	require.NoError(t, env.podNs.Do(func() error {
		l, err := safenetlink.LinkByName("vf0")
		if err != nil {
			return err
		}
		return netlink.LinkSetName(l, "eth9")
	}))

	// StopPodSandbox finds it without a name and moves it back.
	require.NoError(t, hostNs.Do(func() error {
		return env.driver.StopPodSandbox(t.Context(), env.sandbox)
	}))
	require.Empty(t, linkNames(t, env.podNs))
	require.Equal(t, []string{"vf0"}, linkNames(t, hostNs))
}

func TestPrivilegedStopPodSandboxNameTakenOnHost(t *testing.T) {
	env := setupPrivNRIEnv(t)
	hostNs, err := netns.OpenPinned(rootNetNSPath)
	require.NoError(t, err)
	defer hostNs.Close()

	require.NoError(t, hostNs.Do(func() error {
		return env.driver.RunPodSandbox(t.Context(), env.sandbox)
	}))
	// Another link takes the pod-side name on the host meanwhile.
	require.NoError(t, hostNs.Do(func() error {
		return netlink.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "mydevice"}})
	}))

	// The device is renamed back to its kernel name first, so it moves back.
	require.NoError(t, hostNs.Do(func() error {
		return env.driver.StopPodSandbox(t.Context(), env.sandbox)
	}))
	require.Empty(t, linkNames(t, env.podNs))
	require.ElementsMatch(t, []string{"mydevice", "vf0"}, linkNames(t, hostNs))
}

func TestPrivilegedRunPodSandboxFindsRenamedHostLink(t *testing.T) {
	env := setupPrivNRIEnv(t)
	hostNs, err := netns.OpenPinned(rootNetNSPath)
	require.NoError(t, err)
	defer hostNs.Close()

	// The device came back to the host under a previous pod's name, e.g.
	// because that pod's netns was deleted before the driver moved it back.
	require.NoError(t, hostNs.Do(func() error {
		l, err := safenetlink.LinkByName("vf0")
		if err != nil {
			return err
		}
		return netlink.LinkSetName(l, "eswitch0")
	}))

	require.NoError(t, hostNs.Do(func() error {
		return env.driver.RunPodSandbox(t.Context(), env.sandbox)
	}))
	require.Equal(t, []string{"mydevice"}, linkNames(t, env.podNs))
	require.Empty(t, linkNames(t, hostNs))
}

var (
	_ types.Device = (*hostLinkDevice)(nil)
	_ linkFinder   = (*hostLinkDevice)(nil)
)
