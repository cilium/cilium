// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sriov

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// withNetlinkOps replaces all netlink operations with the provided implementation.
// Intended for testing.
func withNetlinkOps(ops netlinkOps) func(*SRIOVManager) {
	return func(s *SRIOVManager) {
		s.nl = ops
	}
}

// withSysPath overrides the sysfs root used for PCI device discovery.
// Intended for testing (point at a t.TempDir() fake sysfs tree).
func withSysPath(p string) func(*SRIOVManager) {
	return func(s *SRIOVManager) {
		s.sysPath = p
	}
}

// ----------------------------------------------------------------------------
// fakeLink — minimal netlink.Link backed by LinkAttrs for use in tests.
// ----------------------------------------------------------------------------

type fakeLink struct {
	attrs netlink.LinkAttrs
}

func (f *fakeLink) Attrs() *netlink.LinkAttrs { return &f.attrs }
func (f *fakeLink) Type() string              { return "fake" }

// newFakeLink constructs a fakeLink with the given name and optional ParentDev
// (PCI address). ParentDev is used by linkAttrsByPCIAddr.
func newFakeLink(name, parentDev string, vfs []netlink.VfInfo) *fakeLink {
	return &fakeLink{
		attrs: netlink.LinkAttrs{
			Name:      name,
			ParentDev: parentDev,
			Vfs:       vfs,
		},
	}
}

// ----------------------------------------------------------------------------
// fakeNetlinkOps — full netlinkOps implementation backed by in-memory state.
//
// Tests construct it via newFakeNetlink() and register links with addLink()
// ----------------------------------------------------------------------------

type fakeNetlinkOps struct {
	// links is the set of links returned by LinkList / LinkByName.
	links []netlink.Link

	// vlanCalls records every LinkSetVfVlan invocation, in order, so tests
	// can assert exactly which VF/VLAN combination Setup/Free requested.
	vlanCalls []vlanCall

	// linkSetVfVlanErr, if set, is returned by every LinkSetVfVlan call.
	linkSetVfVlanErr error
	// linkByNameErr, if set, is returned by every LinkByName call.
	linkByNameErr error
}

// vlanCall records a single LinkSetVfVlan invocation.
type vlanCall struct {
	linkName string
	vf       int
	vlan     int
}

func newFakeNetlink() *fakeNetlinkOps {
	return &fakeNetlinkOps{}
}

// addLink registers a link so it is returned by LinkList and, by name, by LinkByName.
func (f *fakeNetlinkOps) addLink(l netlink.Link) {
	f.links = append(f.links, l)
}

func (f *fakeNetlinkOps) LinkList() ([]netlink.Link, error) {
	return f.links, nil
}

func (f *fakeNetlinkOps) LinkByName(name string) (netlink.Link, error) {
	if f.linkByNameErr != nil {
		return nil, f.linkByNameErr
	}

	for _, l := range f.links {
		if l.Attrs().Name == name {
			return l, nil
		}
	}

	return nil, fmt.Errorf("link %q not found", name)
}

func (f *fakeNetlinkOps) LinkSetVfVlan(link netlink.Link, vf, vlan int) error {
	f.vlanCalls = append(f.vlanCalls, vlanCall{linkName: link.Attrs().Name, vf: vf, vlan: vlan})
	if f.linkSetVfVlanErr != nil {
		return f.linkSetVfVlanErr
	}
	return nil
}

// ----------------------------------------------------------------------------
// fakeSysfs — helpers to build a minimal /sys/bus/pci/devices tree under
// t.TempDir() that SRIOVManager can scan without touching the real system.
//
// Usage:
//
//	fs := newFakeSysfs(t)
//	pf := fs.addPF("0000:01:00.0", "enp1s0f0", pfLink)
//	fs.addVF(pf, "0000:01:00.2", "enp1s0f0v0", vfLink, 0 /*vfID*/)
//	mgr := fs.newManager(t, cfg, nl)
// ----------------------------------------------------------------------------

type fakeSysfs struct {
	t    testing.TB
	root string // t.TempDir()
}

func newFakeSysfs(t testing.TB) *fakeSysfs {
	t.Helper()
	return &fakeSysfs{t: t, root: t.TempDir()}
}

// deviceDir returns the sysfs path for a single PCI device.
func (fs *fakeSysfs) deviceDir(pciAddr string) string {
	return filepath.Join(fs.root, pciDevicesPath, pciAddr)
}

// writeFile writes content to path, creating directories as needed.
func (fs *fakeSysfs) writeFile(path, content string) {
	fs.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fs.t.Fatalf("fakeSysfs: mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		fs.t.Fatalf("fakeSysfs: write %s: %v", path, err)
	}
}

// symlink creates a symlink, creating parent directories as needed.
func (fs *fakeSysfs) symlink(oldname, newname string) {
	fs.t.Helper()
	if err := os.MkdirAll(filepath.Dir(newname), 0o755); err != nil {
		fs.t.Fatalf("fakeSysfs: mkdir for symlink %s: %v", newname, err)
	}
	if err := os.Symlink(oldname, newname); err != nil {
		fs.t.Fatalf("fakeSysfs: symlink %s -> %s: %v", newname, oldname, err)
	}
}

// pfInfo groups the PCI address and kernel ifname of a registered PF.
type pfInfo struct {
	pciAddr string
	ifname  string
	vfCount int // number of VFs added so far
}

// addPF registers a PF device in the fake sysfs. The caller must also add
// the corresponding link to the fakeNetlinkOps (with ParentDev = pciAddr).
// Returns a *pfInfo that addVF uses to attach VFs.
func (fs *fakeSysfs) addPF(pciAddr, ifname string) *pfInfo {
	fs.t.Helper()
	dir := fs.deviceDir(pciAddr)

	// PF is a network device (ethernet class)
	fs.writeFile(filepath.Join(dir, "class"), "0x020000\n")
	// sriov totalvfs / numvfs (defaults; tests can overwrite)
	fs.writeFile(filepath.Join(dir, "sriov_totalvfs"), "4\n")
	fs.writeFile(filepath.Join(dir, "sriov_numvfs"), "0\n")
	// driver symlink — points to a relative driver path under the fake sysfs root
	fs.symlink("../../../../bus/pci/drivers/mlx5_core", filepath.Join(dir, "driver"))

	return &pfInfo{pciAddr: pciAddr, ifname: ifname}
}

// addVF registers a VF device that belongs to the given PF. vfID is the
// index used for the virtfnN symlink on the PF. The caller must also add
// the corresponding link to fakeNetlinkOps (with ParentDev = vfPCIAddr).
func (fs *fakeSysfs) addVF(pf *pfInfo, vfPCIAddr, ifname string, vfID int) {
	fs.t.Helper()
	vfDir := fs.deviceDir(vfPCIAddr)

	fs.writeFile(filepath.Join(vfDir, "class"), "0x020000\n")
	fs.symlink("../../../../bus/pci/drivers/mlx5_core", filepath.Join(vfDir, "driver"))
	fs.writeFile(filepath.Join(vfDir, "vendor"), "0x15b3\n")
	fs.writeFile(filepath.Join(vfDir, "device"), "0x1016\n")

	// physfn symlink: VF -> PF
	fs.symlink(fmt.Sprintf("../%s", pf.pciAddr), filepath.Join(vfDir, "physfn"))

	// virtfnN symlink on PF: PF -> VF
	pfDir := fs.deviceDir(pf.pciAddr)
	fs.symlink(fmt.Sprintf("../%s", vfPCIAddr), filepath.Join(pfDir, fmt.Sprintf("virtfn%d", vfID)))

	pf.vfCount++
	_ = ifname // ifname comes from the fakeNetlinkOps link, not sysfs
}

// newManager constructs a real SRIOVManager pointed at this fake sysfs and
// using the provided netlinkOps. init() (setupVfs) is called with the ifaces
// in cfg — pass newSRIOVCfg().build() with no ifaces to skip VF provisioning.
func (fs *fakeSysfs) newManager(t testing.TB, cfg *v2alpha1.SRIOVDeviceManagerConfig, nl netlinkOps) *SRIOVManager {
	t.Helper()
	mgr := &SRIOVManager{
		logger:  hivetest.Logger(t),
		sysPath: fs.root,
		config:  cfg,
		nl:      nl,
	}
	return mgr
}

func TestSriov(t *testing.T) {
	// Build a fake sysfs with one PF (0000:02:00.0) and one VF (0000:02:00.1, vfID=1).
	// The netlink layer reports the PF as "mypf" and the VF as "myvf".
	// VF sysfs attributes are: driver=mydriver, vendor=myvendor, device=mydeviceid.
	setupFakes := func(t *testing.T) (*fakeSysfs, *fakeNetlinkOps) {
		t.Helper()
		fs := newFakeSysfs(t)
		nl := newFakeNetlink()

		pf := fs.addPF("0000:02:00.0", "mypf")
		fs.addVF(pf, "0000:02:00.1", "myvf", 1)

		// Override the default vendor/device/driver written by addVF with test-specific values.
		fs.writeFile(filepath.Join(fs.deviceDir("0000:02:00.1"), "vendor"), "myvendor\n")
		fs.writeFile(filepath.Join(fs.deviceDir("0000:02:00.1"), "device"), "mydeviceid\n")
		driverLink := filepath.Join(fs.deviceDir("0000:02:00.1"), "driver")
		os.Remove(driverLink)
		fs.symlink("../../../../bus/pci/drivers/mydriver", driverLink)

		nl.addLink(newFakeLink("mypf", "0000:02:00.0", []netlink.VfInfo{{ID: 1}}))
		nl.addLink(newFakeLink("myvf", "0000:02:00.1", nil))

		return fs, nl
	}

	t.Run("setup on startup", func(t *testing.T) {
		fs, nl := setupFakes(t)
		cfg := v2alpha1.SRIOVDeviceManagerConfig{
			Ifaces: []v2alpha1.SRIOVDeviceConfig{
				{IfName: "mypf", VFCount: 1},
			},
		}

		// NewManager calls init() → setupVfs(), which writes sriov_numvfs=1.
		mgr, err := NewManager(hivetest.Logger(t), &cfg, withNetlinkOps(nl), withSysPath(fs.root))
		require.NoError(t, err)

		// Verify sriov_numvfs was written.
		numVfs, err := os.ReadFile(filepath.Join(mgr.pciDevicesPath(), "0000:02:00.0", "sriov_numvfs"))
		require.NoError(t, err)
		require.Equal(t, "1", strings.TrimSpace(string(numVfs)))
	})

	t.Run("device parsing", func(t *testing.T) {
		fs, nl := setupFakes(t)
		// No ifaces → setupVfs is a no-op, nothing mutates sysfs.
		cfg := v2alpha1.SRIOVDeviceManagerConfig{}
		mgr := fs.newManager(t, &cfg, nl)

		byPCI, err := mgr.linkAttrsByPCIAddr()
		require.NoError(t, err)
		require.Contains(t, byPCI, PCIAddr("0000:02:00.1"))

		device, err := mgr.parseDevice("0000:02:00.1", byPCI)
		require.NoError(t, err)
		require.NotNil(t, device)

		expectedDevice := PciDevice{
			Addr:            "0000:02:00.1",
			PFName:          "mypf",
			Driver:          "mydriver",
			VFID:            1,
			KernelIfaceName: "myvf",
			DeviceID:        "mydeviceid",
			Vendor:          "myvendor",
		}

		require.Equal(t, expectedDevice, *device)
		require.ElementsMatch(t, slices.Collect(maps.Keys(expectedDevice.GetAttrs())), slices.Collect(maps.Keys(device.GetAttrs())))
		for k, v := range expectedDevice.GetAttrs() {
			require.Equal(t, v, device.GetAttrs()[k])
		}
	})
}

// TestPciDevice_Match covers the Match() method across all filter fields,
// including the no-kernel-interface (DPDK/vfio) case.
//
// Note: for SR-IOV devices, IfNames matches against the kernel interface name
// (e.g. "ens1f0v0"). Devices bound to userspace drivers (vfio-pci) have an
// empty KernelIfName and cannot be selected via IfNames; use PfNames or
// PCIAddrs instead.
func TestPciDevice_Match(t *testing.T) {
	// baseline is a typical SR-IOV VF with a kernel netdev.
	baseline := PciDevice{
		Addr:            "0000:03:00.1",
		Driver:          "mlx5_core",
		Vendor:          "0x15b3",
		DeviceID:        "0x1018",
		PFName:          "ens1f0",
		VFID:            0,
		KernelIfaceName: "ens1f0v0",
	}

	// noKernel is bound to a userspace driver and has no kernel netdev.
	noKernel := PciDevice{
		Addr:            "0000:03:00.1",
		Driver:          "vfio-pci",
		Vendor:          "0x15b3",
		DeviceID:        "0x1018",
		PFName:          "ens1f0",
		VFID:            0,
		KernelIfaceName: "",
	}

	tests := []struct {
		name   string
		dev    PciDevice
		filter v2alpha1.CiliumNetworkDriverDeviceFilter
		want   bool
	}{
		// ── deviceManagers ────────────────────────────────────────────────
		{
			name:   "empty filter matches",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{},
			want:   true,
		},
		{
			name:   "matching device manager",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceManagers: []string{"sr-iov"}},
			want:   true,
		},
		{
			name:   "non-matching device manager",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceManagers: []string{"dummy"}},
			want:   false,
		},

		// ── ifNames: matches the kernel interface name, not the synthetic PCI-derived name ──
		{
			name:   "ifNames matches kernel interface name",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"ens1f0v0"}},
			want:   true,
		},
		{
			name:   "ifNames with synthetic PCI name does not match",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"0000-03-00-1"}},
			want:   false,
		},
		{
			name:   "ifNames non-matching",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"eth0"}},
			want:   false,
		},
		{
			name:   "ifNames multiple candidates, kernel name present",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"eth0", "ens1f0v0"}},
			want:   true,
		},

		// ── ifNames on device with no kernel interface (DPDK/vfio) ────────
		{
			name:   "ifNames does not match empty KernelIfName",
			dev:    noKernel,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"ens1f0v0"}},
			want:   false,
		},
		{
			name:   "pciAddrs matches device with no kernel interface",
			dev:    noKernel,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{PCIAddrs: []string{"0000:03:00.1"}},
			want:   true,
		},

		// ── PCI-specific fields ───────────────────────────────────────────
		{
			name:   "pciAddrs exact match",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{PCIAddrs: []string{"0000:03:00.1"}},
			want:   true,
		},
		{
			name:   "pciAddrs non-matching",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{PCIAddrs: []string{"0000:03:00.0"}},
			want:   false,
		},
		{
			name:   "vendorIDs match",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{VendorIDs: []string{"0x15b3"}},
			want:   true,
		},
		{
			name:   "vendorIDs non-matching",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{VendorIDs: []string{"0x8086"}},
			want:   false,
		},
		{
			name:   "deviceIDs match",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceIDs: []string{"0x1018"}},
			want:   true,
		},
		{
			name:   "deviceIDs non-matching",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceIDs: []string{"0xdead"}},
			want:   false,
		},
		{
			name:   "drivers match",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{Drivers: []string{"mlx5_core"}},
			want:   true,
		},
		{
			name:   "drivers non-matching",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{Drivers: []string{"vfio-pci"}},
			want:   false,
		},

		// ── pfNames: SR-IOV Physical Function filter ──────────────────────
		{
			name:   "pfNames matches PF name",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{PFNames: []string{"ens1f0"}},
			want:   true,
		},
		{
			name:   "pfNames non-matching",
			dev:    baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{PFNames: []string{"ens2f0"}},
			want:   false,
		},

		// ── combinations ──────────────────────────────────────────────────
		{
			name: "deviceManager + pciAddr + vendor all match",
			dev:  baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				DeviceManagers: []string{"sr-iov"},
				PCIAddrs:       []string{"0000:03:00.1"},
				VendorIDs:      []string{"0x15b3"},
			},
			want: true,
		},
		{
			name: "deviceManager + pfNames + driver all match",
			dev:  baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				DeviceManagers: []string{"sr-iov"},
				PFNames:        []string{"ens1f0"},
				Drivers:        []string{"mlx5_core"},
			},
			want: true,
		},
		{
			name: "ifNames (kernel) + pciAddr both match",
			dev:  baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				IfNames:  []string{"ens1f0v0"},
				PCIAddrs: []string{"0000:03:00.1"},
			},
			want: true,
		},
		{
			name: "ifNames matches kernel but vendor does not",
			dev:  baseline,
			filter: v2alpha1.CiliumNetworkDriverDeviceFilter{
				IfNames:   []string{"ens1f0v0"},
				VendorIDs: []string{"0x8086"},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.dev.Match(tt.filter))
		})
	}
}

// ----------------------------------------------------------------------------
// TestPciDevice_SetupFree — covers VLAN configuration on Setup/Free, and the
// not-a-VF guard when PFName is empty. This is the unit-testable equivalent
// of sriov-test.sh's TC-4 (VLAN set on Setup, reset to 0 on Free), without
// requiring real hardware: fakeNetlinkOps.LinkSetVfVlan records every call so
// we can assert exactly which VF/VLAN combination was requested.
// ----------------------------------------------------------------------------

func TestPciDevice_SetupFree(t *testing.T) {
	newDev := func() (PciDevice, *fakeNetlinkOps) {
		nl := newFakeNetlink()
		nl.addLink(newFakeLink("ens1f0", "0000:03:00.0", nil))
		dev := PciDevice{
			Addr:            "0000:03:00.1",
			PFName:          "ens1f0",
			VFID:            2,
			KernelIfaceName: "ens1f0v2",
			nl:              nl,
		}
		return dev, nl
	}

	t.Run("Setup with vlan set calls LinkSetVfVlan with the configured vlan", func(t *testing.T) {
		dev, nl := newDev()

		err := dev.Setup(types.DeviceConfig{Vlan: 100})
		require.NoError(t, err)

		require.Equal(t, []vlanCall{{linkName: "ens1f0", vf: 2, vlan: 100}}, nl.vlanCalls)
	})

	t.Run("Setup with vlan zero does not call LinkSetVfVlan", func(t *testing.T) {
		dev, nl := newDev()

		err := dev.Setup(types.DeviceConfig{Vlan: 0})
		require.NoError(t, err)

		require.Empty(t, nl.vlanCalls)
	})

	t.Run("Free with vlan previously set resets vlan to 0", func(t *testing.T) {
		dev, nl := newDev()

		// Free is called with the same config the claim requested (vlan=100);
		// the driver must reset the VF's VLAN to 0 regardless.
		err := dev.Free(types.DeviceConfig{Vlan: 100})
		require.NoError(t, err)

		require.Equal(t, []vlanCall{{linkName: "ens1f0", vf: 2, vlan: 0}}, nl.vlanCalls)
	})

	t.Run("Free with vlan zero does not call LinkSetVfVlan", func(t *testing.T) {
		dev, nl := newDev()

		err := dev.Free(types.DeviceConfig{Vlan: 0})
		require.NoError(t, err)

		require.Empty(t, nl.vlanCalls)
	})

	t.Run("Setup fails fast when PFName is empty (not a VF)", func(t *testing.T) {
		dev, nl := newDev()
		dev.PFName = ""

		err := dev.Setup(types.DeviceConfig{Vlan: 100})
		require.ErrorIs(t, err, errNotAVF)
		require.Empty(t, nl.vlanCalls)
	})

	t.Run("Free fails fast when PFName is empty (not a VF)", func(t *testing.T) {
		dev, nl := newDev()
		dev.PFName = ""

		err := dev.Free(types.DeviceConfig{Vlan: 100})
		require.ErrorIs(t, err, errNotAVF)
		require.Empty(t, nl.vlanCalls)
	})

	t.Run("Setup propagates LinkByName error", func(t *testing.T) {
		dev, nl := newDev()
		nl.linkByNameErr = fmt.Errorf("boom")

		err := dev.Setup(types.DeviceConfig{Vlan: 100})
		require.Error(t, err)
	})

	t.Run("Setup propagates LinkSetVfVlan error", func(t *testing.T) {
		dev, nl := newDev()
		nl.linkSetVfVlanErr = fmt.Errorf("boom")

		err := dev.Setup(types.DeviceConfig{Vlan: 100})
		require.Error(t, err)
	})

	t.Run("Free propagates LinkByName error", func(t *testing.T) {
		dev, nl := newDev()
		nl.linkByNameErr = fmt.Errorf("boom")

		err := dev.Free(types.DeviceConfig{Vlan: 100})
		require.Error(t, err)
	})

	t.Run("Free propagates LinkSetVfVlan error", func(t *testing.T) {
		dev, nl := newDev()
		nl.linkSetVfVlanErr = fmt.Errorf("boom")

		err := dev.Free(types.DeviceConfig{Vlan: 100})
		require.Error(t, err)
	})
}

// ----------------------------------------------------------------------------
// TestPciDevice_Merge — covers carrying KernelIfName forward across a rescan
// that cannot determine one (e.g. the VF has moved into a pod's netns and its
// sysfs net/ entry is gone). This is the unit-testable equivalent of
// sriov-test.sh's TC-8.
// ----------------------------------------------------------------------------

func TestPciDevice_Merge(t *testing.T) {
	t.Run("carries KernelIfName forward when fresh scan found none", func(t *testing.T) {
		old := &PciDevice{KernelIfaceName: "ens1f1v0"}
		fresh := &PciDevice{}

		fresh.Merge(old)

		require.Equal(t, "ens1f1v0", fresh.KernelIfName())
	})

	t.Run("overwrites KernelIfName on update, updates driver", func(t *testing.T) {
		old := &PciDevice{
			KernelIfaceName: "ens1f1v0",
			Driver:          "iavf",
		}

		fresh := &PciDevice{
			KernelIfaceName: "ens1f1v0-renamed",
			Driver:          "mlx5_core",
		}

		fresh.Merge(old)

		require.Equal(t, "ens1f1v0-renamed", fresh.KernelIfName())
		require.Equal(t, "mlx5_core", fresh.Driver)
	})
}

// ----------------------------------------------------------------------------
// TestPciDevice_MarshalUnmarshalRoundTrip — guards against the class of bug
// where a custom (Un)MarshalBinary/TextMarshaler double-encodes or otherwise
// loses data. PciDevice's Marshal/UnmarshalBinary are the wire format used to
// persist allocations across an agent restart (see RestoreDevice), so a
// silent round-trip failure here would manifest as sriov-test.sh's TC-7/TC-8
// restore-from-claim checks failing on real hardware.
// ----------------------------------------------------------------------------

func TestPciDevice_MarshalUnmarshalRoundTrip(t *testing.T) {
	orig := PciDevice{
		Addr:            "0000:03:00.1",
		Driver:          "mlx5_core",
		Vendor:          "0x15b3",
		DeviceID:        "0x1018",
		PFName:          "ens1f0",
		VFID:            2,
		KernelIfaceName: "ens1f0v2",
	}

	data, err := orig.MarshalBinary()
	require.NoError(t, err)

	var got PciDevice
	require.NoError(t, got.UnmarshalBinary(data))

	require.Equal(t, orig, got)
}

// ----------------------------------------------------------------------------
// TestSetupVFs — covers setupVFs' branches beyond the happy path already
// exercised by TestSriov's "setup on startup" subtest: too-many-VFs,
// interface-not-found, and the already-configured skip path (both matching
// and differing VF counts). All pure logic against fakeSysfs — no hardware.
// ----------------------------------------------------------------------------

func TestSetupVFs(t *testing.T) {
	t.Run("no ifaces is a no-op", func(t *testing.T) {
		fs := newFakeSysfs(t)
		nl := newFakeNetlink()
		mgr := fs.newManager(t, &v2alpha1.SRIOVDeviceManagerConfig{}, nl)

		require.NoError(t, mgr.setupVFs(nil))
	})

	t.Run("interface not found in netlink returns errInterfaceNotFound", func(t *testing.T) {
		fs := newFakeSysfs(t)
		nl := newFakeNetlink() // no links registered

		mgr := fs.newManager(t, &v2alpha1.SRIOVDeviceManagerConfig{}, nl)
		err := mgr.setupVFs([]v2alpha1.SRIOVDeviceConfig{{IfName: "ens1f0", VFCount: 1}})
		require.ErrorIs(t, err, errInterfaceNotFound)
	})

	t.Run("requested VFCount exceeds sriov_totalvfs returns errTooManyVFs", func(t *testing.T) {
		fs := newFakeSysfs(t)
		nl := newFakeNetlink()
		fs.addPF("0000:02:00.0", "ens1f0") // sriov_totalvfs defaults to 4
		nl.addLink(newFakeLink("ens1f0", "0000:02:00.0", nil))

		mgr := fs.newManager(t, &v2alpha1.SRIOVDeviceManagerConfig{}, nl)
		err := mgr.setupVFs([]v2alpha1.SRIOVDeviceConfig{{IfName: "ens1f0", VFCount: 5}})
		require.ErrorIs(t, err, errTooManyVFs)

		// sriov_numvfs must remain untouched (still 0).
		numVfs, rerr := os.ReadFile(filepath.Join(mgr.pciDevicesPath(), "0000:02:00.0", "sriov_numvfs"))
		require.NoError(t, rerr)
		require.Equal(t, "0", strings.TrimSpace(string(numVfs)))
	})

	t.Run("already configured with matching VFCount is left untouched", func(t *testing.T) {
		fs := newFakeSysfs(t)
		nl := newFakeNetlink()
		fs.addPF("0000:02:00.0", "ens1f0")
		fs.writeFile(filepath.Join(fs.deviceDir("0000:02:00.0"), "sriov_numvfs"), "2\n")
		nl.addLink(newFakeLink("ens1f0", "0000:02:00.0", nil))

		mgr := fs.newManager(t, &v2alpha1.SRIOVDeviceManagerConfig{}, nl)
		require.NoError(t, mgr.setupVFs([]v2alpha1.SRIOVDeviceConfig{{IfName: "ens1f0", VFCount: 2}}))

		numVfs, err := os.ReadFile(filepath.Join(mgr.pciDevicesPath(), "0000:02:00.0", "sriov_numvfs"))
		require.NoError(t, err)
		require.Equal(t, "2", strings.TrimSpace(string(numVfs)))
	})

	t.Run("already configured with differing VFCount logs a warning but is left untouched", func(t *testing.T) {
		fs := newFakeSysfs(t)
		nl := newFakeNetlink()
		fs.addPF("0000:02:00.0", "ens1f0")
		fs.writeFile(filepath.Join(fs.deviceDir("0000:02:00.0"), "sriov_numvfs"), "2\n")
		nl.addLink(newFakeLink("ens1f0", "0000:02:00.0", nil))

		mgr := fs.newManager(t, &v2alpha1.SRIOVDeviceManagerConfig{}, nl)
		// VFCount=3 differs from the already-configured 2; setupVFs must not
		// error and must not touch sriov_numvfs (existing VFs are never disrupted).
		require.NoError(t, mgr.setupVFs([]v2alpha1.SRIOVDeviceConfig{{IfName: "ens1f0", VFCount: 3}}))

		numVfs, err := os.ReadFile(filepath.Join(mgr.pciDevicesPath(), "0000:02:00.0", "sriov_numvfs"))
		require.NoError(t, err)
		require.Equal(t, "2", strings.TrimSpace(string(numVfs)))
	})

	t.Run("fresh PF gets sriov_numvfs written", func(t *testing.T) {
		fs := newFakeSysfs(t)
		nl := newFakeNetlink()
		fs.addPF("0000:02:00.0", "ens1f0") // sriov_numvfs defaults to 0
		nl.addLink(newFakeLink("ens1f0", "0000:02:00.0", nil))

		mgr := fs.newManager(t, &v2alpha1.SRIOVDeviceManagerConfig{}, nl)
		require.NoError(t, mgr.setupVFs([]v2alpha1.SRIOVDeviceConfig{{IfName: "ens1f0", VFCount: 3}}))

		numVfs, err := os.ReadFile(filepath.Join(mgr.pciDevicesPath(), "0000:02:00.0", "sriov_numvfs"))
		require.NoError(t, err)
		require.Equal(t, "3", strings.TrimSpace(string(numVfs)))
	})

	t.Run("multiple ifaces: one fails with errTooManyVFs, other still gets configured", func(t *testing.T) {
		fs := newFakeSysfs(t)
		nl := newFakeNetlink()
		fs.addPF("0000:02:00.0", "ens1f0")
		fs.addPF("0000:03:00.0", "ens1f1")
		nl.addLink(newFakeLink("ens1f0", "0000:02:00.0", nil))
		nl.addLink(newFakeLink("ens1f1", "0000:03:00.0", nil))

		mgr := fs.newManager(t, &v2alpha1.SRIOVDeviceManagerConfig{}, nl)
		err := mgr.setupVFs([]v2alpha1.SRIOVDeviceConfig{
			{IfName: "ens1f0", VFCount: 100}, // exceeds totalvfs=4
			{IfName: "ens1f1", VFCount: 2},
		})
		require.ErrorIs(t, err, errTooManyVFs)

		numVfs0, rerr := os.ReadFile(filepath.Join(mgr.pciDevicesPath(), "0000:02:00.0", "sriov_numvfs"))
		require.NoError(t, rerr)
		require.Equal(t, "0", strings.TrimSpace(string(numVfs0)))

		numVfs1, rerr := os.ReadFile(filepath.Join(mgr.pciDevicesPath(), "0000:03:00.0", "sriov_numvfs"))
		require.NoError(t, rerr)
		require.Equal(t, "2", strings.TrimSpace(string(numVfs1)))
	})
}
