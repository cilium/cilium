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
	resourceapi "k8s.io/api/resource/v1"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
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
	for _, l := range f.links {
		if l.Attrs().Name == name {
			return l, nil
		}
	}

	return nil, fmt.Errorf("link %q not found", name)
}

func (f *fakeNetlinkOps) LinkSetVfVlan(link netlink.Link, vf, vlan int) error {
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

func compareAttrs(t *testing.T, one, two map[resourceapi.QualifiedName]resourceapi.DeviceAttribute) {
	require.NotEmpty(t, one)
	require.ElementsMatch(t, slices.Collect(maps.Keys(one)), slices.Collect(maps.Keys(two)))

	for k, v := range one {
		require.NotEmpty(t, v.String())
		other := two[k]
		require.Equal(t, v.String(), other.String())
	}
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
		compareAttrs(t, device.GetAttrs(), expectedDevice.GetAttrs())
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
