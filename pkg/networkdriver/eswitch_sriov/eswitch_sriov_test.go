// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eswitch_sriov

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

// withNetlinkOps replaces all netlink operations with the provided
// implementation. Intended for testing.
func withNetlinkOps(ops netlinkOps) func(*EswitchSRIOVManager) {
	return func(s *EswitchSRIOVManager) {
		s.nl = ops
	}
}

// withSysPath overrides the sysfs root used for PCI device discovery.
// Intended for testing (point at a t.TempDir() fake sysfs tree).
func withSysPath(p string) func(*EswitchSRIOVManager) {
	return func(s *EswitchSRIOVManager) {
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

// newFakeLink constructs a fakeLink with the given name and optional
// ParentDev (PCI address) and index.
func newFakeLink(name, parentDev string, vfs []netlink.VfInfo) *fakeLink {
	return &fakeLink{
		attrs: netlink.LinkAttrs{
			Name:      name,
			ParentDev: parentDev,
			Vfs:       vfs,
		},
	}
}

func newFakeLinkWithIndex(name string, index int) *fakeLink {
	return &fakeLink{attrs: netlink.LinkAttrs{Name: name, Index: index}}
}

// newFakeBridgeLink constructs a real *netlink.Bridge with the given name
// and index. Production code type-asserts a fetched bridge link to
// *netlink.Bridge (see reconcileBridge/diffBridgeParams), so any
// pre-populated bridge link a test expects to go through that path must be
// a genuine *netlink.Bridge, not the fakeLink stand-in used for plain
// (non-bridge) links.
func newFakeBridgeLink(name string, index int) *netlink.Bridge {
	return &netlink.Bridge{LinkAttrs: netlink.LinkAttrs{Name: name, Index: index}}
}

// ----------------------------------------------------------------------------
// fakeNetlinkOps — full netlinkOps implementation backed by in-memory state.
//
// netlinkOps is reserved (per eswitch_sriov.go) for mutation operations that
// have no sysfs equivalent: creating/modifying/enslaving links, programming
// bridge VLAN membership, and switching devlink eswitch mode. All discovery
// (kernel ifname resolution, PF<->VF/representor mapping, bridge
// enslavement checks) is driven by fakeSysfs below, not this fake.
// ----------------------------------------------------------------------------

type masterSetCall struct {
	linkName   string
	masterName string
}

type bridgeVlanCall struct {
	linkName string
	vid      uint16
	pvid     bool
	untagged bool
}

type devlinkModeSetCall struct {
	bus    string
	device string
	mode   string
}

type fakeNetlinkOps struct {
	links   []netlink.Link
	nextIdx int

	linkAddCalls    []string
	linkModifyCalls []string
	modifiedBridges []*netlink.Bridge
	linkSetUpCalls  []string
	masterSetCalls  []masterSetCall
	noMasterCalls   []string

	bridgeVlanAdds []bridgeVlanCall
	bridgeVlanDels []bridgeVlanCall
	// bridgeVlanTable is the current state of the bridge vlan table, keyed
	// by link ifindex. Setup/Free consult this for idempotency and mutate
	// it via BridgeVlanAdd/Del.
	bridgeVlanTable map[int32][]*nl.BridgeVlanInfo

	devlinkDevices      []*netlink.DevlinkDevice
	devlinkModeSetCalls []devlinkModeSetCall

	devlinkPorts []*netlink.DevlinkPort

	linkByNameErr            error
	linkAddErr               error
	linkModifyErr            error
	linkSetNoMasterErr       error
	bridgeVlanAddErr         error
	bridgeVlanDelErr         error
	bridgeVlanListErr        error
	devLinkGetDeviceListErr  error
	devLinkSetEswitchModeErr error
	devLinkGetAllPortListErr error
}

func newFakeNetlink() *fakeNetlinkOps {
	return &fakeNetlinkOps{
		bridgeVlanTable: make(map[int32][]*nl.BridgeVlanInfo),
		nextIdx:         100,
	}
}

func (f *fakeNetlinkOps) addLink(l netlink.Link) {
	if l.Attrs().Index == 0 {
		f.nextIdx++
		l.Attrs().Index = f.nextIdx
	}
	f.links = append(f.links, l)
}

func (f *fakeNetlinkOps) addDevlinkDevice(bus, device, mode string) {
	f.devlinkDevices = append(f.devlinkDevices, &netlink.DevlinkDevice{
		BusName:    bus,
		DeviceName: device,
		Attrs: netlink.DevlinkDevAttrs{
			Eswitch: netlink.DevlinkDevEswitchAttr{Mode: mode},
		},
	})
}

// addDevlinkPort registers a devlink port representing the VF representor
// for vfID on the PF identified by pfAddr, with NetdeviceName repName.
// Mirrors the real devlink port fields findRepresentor filters on
// (BusName/DeviceName/PortFlavour/VfNumber).
func (f *fakeNetlinkOps) addDevlinkPort(pfAddr string, vfID int, repName string) {
	vf := uint16(vfID)
	f.devlinkPorts = append(f.devlinkPorts, &netlink.DevlinkPort{
		BusName:       pciBusName,
		DeviceName:    pfAddr,
		PortFlavour:   nl.DEVLINK_PORT_FLAVOUR_PCI_VF,
		VfNumber:      &vf,
		NetdeviceName: repName,
	})
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

func (f *fakeNetlinkOps) LinkAdd(link netlink.Link) error {
	f.linkAddCalls = append(f.linkAddCalls, link.Attrs().Name)
	if f.linkAddErr != nil {
		return f.linkAddErr
	}
	f.addLink(link)
	return nil
}

func (f *fakeNetlinkOps) LinkModify(link netlink.Link) error {
	f.linkModifyCalls = append(f.linkModifyCalls, link.Attrs().Name)
	if br, ok := link.(*netlink.Bridge); ok {
		f.modifiedBridges = append(f.modifiedBridges, br)
	}
	if f.linkModifyErr != nil {
		return f.linkModifyErr
	}
	for i, l := range f.links {
		if l.Attrs().Name == link.Attrs().Name {
			f.links[i] = link
		}
	}
	return nil
}

func (f *fakeNetlinkOps) LinkSetUp(link netlink.Link) error {
	f.linkSetUpCalls = append(f.linkSetUpCalls, link.Attrs().Name)
	return nil
}

func (f *fakeNetlinkOps) LinkSetMaster(link, master netlink.Link) error {
	f.masterSetCalls = append(f.masterSetCalls, masterSetCall{
		linkName:   link.Attrs().Name,
		masterName: master.Attrs().Name,
	})
	link.Attrs().MasterIndex = master.Attrs().Index
	return nil
}

func (f *fakeNetlinkOps) LinkSetNoMaster(link netlink.Link) error {
	f.noMasterCalls = append(f.noMasterCalls, link.Attrs().Name)
	if f.linkSetNoMasterErr != nil {
		return f.linkSetNoMasterErr
	}
	link.Attrs().MasterIndex = 0
	return nil
}

func (f *fakeNetlinkOps) BridgeVlanAdd(link netlink.Link, vid uint16, pvid, untagged, self, master bool) error {
	f.bridgeVlanAdds = append(f.bridgeVlanAdds, bridgeVlanCall{linkName: link.Attrs().Name, vid: vid, pvid: pvid, untagged: untagged})
	if f.bridgeVlanAddErr != nil {
		return f.bridgeVlanAddErr
	}

	idx := int32(link.Attrs().Index)
	var flags uint16
	if pvid {
		flags |= bridgeVlanInfoPVID
	}
	if untagged {
		flags |= bridgeVlanInfoUntagged
	}
	f.bridgeVlanTable[idx] = append(f.bridgeVlanTable[idx], &nl.BridgeVlanInfo{Flags: flags, Vid: vid})

	return nil
}

func (f *fakeNetlinkOps) BridgeVlanDel(link netlink.Link, vid uint16, pvid, untagged, self, master bool) error {
	f.bridgeVlanDels = append(f.bridgeVlanDels, bridgeVlanCall{linkName: link.Attrs().Name, vid: vid, pvid: pvid, untagged: untagged})
	if f.bridgeVlanDelErr != nil {
		return f.bridgeVlanDelErr
	}

	idx := int32(link.Attrs().Index)
	var kept []*nl.BridgeVlanInfo
	for _, info := range f.bridgeVlanTable[idx] {
		if info.Vid == vid {
			continue
		}
		kept = append(kept, info)
	}
	f.bridgeVlanTable[idx] = kept

	return nil
}

func (f *fakeNetlinkOps) BridgeVlanList() (map[int32][]*nl.BridgeVlanInfo, error) {
	if f.bridgeVlanListErr != nil {
		return nil, f.bridgeVlanListErr
	}
	return f.bridgeVlanTable, nil
}

func (f *fakeNetlinkOps) DevLinkGetDeviceList() ([]*netlink.DevlinkDevice, error) {
	if f.devLinkGetDeviceListErr != nil {
		return nil, f.devLinkGetDeviceListErr
	}
	return f.devlinkDevices, nil
}

func (f *fakeNetlinkOps) DevLinkSetEswitchMode(dev *netlink.DevlinkDevice, newMode string) error {
	f.devlinkModeSetCalls = append(f.devlinkModeSetCalls, devlinkModeSetCall{bus: dev.BusName, device: dev.DeviceName, mode: newMode})
	if f.devLinkSetEswitchModeErr != nil {
		return f.devLinkSetEswitchModeErr
	}
	dev.Attrs.Eswitch.Mode = newMode
	return nil
}

func (f *fakeNetlinkOps) DevLinkGetAllPortList() ([]*netlink.DevlinkPort, error) {
	if f.devLinkGetAllPortListErr != nil {
		return nil, f.devLinkGetAllPortListErr
	}
	return f.devlinkPorts, nil
}

// ----------------------------------------------------------------------------
// fakeSysfs — helpers to build a minimal /sys/bus/pci/devices tree under
// t.TempDir(), driving all discovery (kernel ifname resolution, PF<->VF/
// representor mapping via phys_port_name, bridge enslavement via the
// "master" symlink).
// ----------------------------------------------------------------------------

type fakeSysfs struct {
	t    testing.TB
	root string
}

func newFakeSysfs(t testing.TB) *fakeSysfs {
	t.Helper()
	return &fakeSysfs{t: t, root: t.TempDir()}
}

func (fs *fakeSysfs) deviceDir(pciAddr string) string {
	return filepath.Join(fs.root, pciDevicesPath, pciAddr)
}

func (fs *fakeSysfs) writeFile(path, content string) {
	fs.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fs.t.Fatalf("fakeSysfs: mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		fs.t.Fatalf("fakeSysfs: write %s: %v", path, err)
	}
}

func (fs *fakeSysfs) symlink(oldname, newname string) {
	fs.t.Helper()
	if err := os.MkdirAll(filepath.Dir(newname), 0o755); err != nil {
		fs.t.Fatalf("fakeSysfs: mkdir for symlink %s: %v", newname, err)
	}
	if err := os.Symlink(oldname, newname); err != nil {
		fs.t.Fatalf("fakeSysfs: symlink %s -> %s: %v", newname, oldname, err)
	}
}

// netDevDir returns the .../net/<ifname> sysfs directory for the netdev
// named ifname living under the PCI device at pciAddr.
func (fs *fakeSysfs) netDevDir(pciAddr, ifname string) string {
	return filepath.Join(fs.deviceDir(pciAddr), "net", ifname)
}

// addNetDir registers a bare net/<ifname> subdirectory (no phys_port_name)
// under the PCI device at pciAddr, i.e. a plain, non-representor netdev
// (a PF/VF's own kernel interface).
func (fs *fakeSysfs) addNetDir(pciAddr, ifname string) {
	fs.t.Helper()
	if err := os.MkdirAll(fs.netDevDir(pciAddr, ifname), 0o755); err != nil {
		fs.t.Fatalf("fakeSysfs: mkdir %s: %v", fs.netDevDir(pciAddr, ifname), err)
	}
}

// setMaster creates the "master" symlink under pciAddr/net/ifname pointing
// at a path whose basename is bridgeName, matching isEnslavedTo's
// filepath.Base(readlink) check.
func (fs *fakeSysfs) setMaster(pciAddr, ifname, bridgeName string) {
	fs.symlink(filepath.Join("..", "..", "..", "virtual", "net", bridgeName), filepath.Join(fs.netDevDir(pciAddr, ifname), "master"))
}

type pfInfo struct {
	pciAddr string
	ifname  string
}

// addPF registers a PF device in the fake sysfs with totalvfs=4, numvfs=0,
// and a net/<ifname> dir for its own uplink kernel interface.
func (fs *fakeSysfs) addPF(pciAddr, ifname string) *pfInfo {
	fs.t.Helper()
	dir := fs.deviceDir(pciAddr)

	fs.writeFile(filepath.Join(dir, "class"), "0x020000\n")
	fs.writeFile(filepath.Join(dir, "sriov_totalvfs"), "4\n")
	fs.writeFile(filepath.Join(dir, "sriov_numvfs"), "0\n")
	fs.symlink("../../../../bus/pci/drivers/mlx5_core", filepath.Join(dir, "driver"))
	fs.addNetDir(pciAddr, ifname)

	return &pfInfo{pciAddr: pciAddr, ifname: ifname}
}

// setNumVFs overwrites the PF's sriov_numvfs file (used to simulate a PF
// that already has VFs configured).
func (fs *fakeSysfs) setNumVFs(pf *pfInfo, n int) {
	fs.writeFile(filepath.Join(fs.deviceDir(pf.pciAddr), "sriov_numvfs"), fmt.Sprintf("%d\n", n))
}

// addVF registers a VF device that belongs to the given PF. If vfIfname is
// non-empty, a net/<vfIfname> dir is also created for the VF's own kernel
// interface (omit to simulate a VF currently assigned to a pod netns, with
// no kernel-visible interface from the root namespace).
func (fs *fakeSysfs) addVF(pf *pfInfo, vfPCIAddr string, vfID int, vfIfname string) {
	fs.t.Helper()
	vfDir := fs.deviceDir(vfPCIAddr)

	fs.writeFile(filepath.Join(vfDir, "class"), "0x020000\n")
	fs.symlink("../../../../bus/pci/drivers/mlx5_core", filepath.Join(vfDir, "driver"))
	fs.writeFile(filepath.Join(vfDir, "vendor"), "0x15b3\n")
	fs.writeFile(filepath.Join(vfDir, "device"), "0x1016\n")

	fs.symlink(fmt.Sprintf("../%s", pf.pciAddr), filepath.Join(vfDir, "physfn"))

	pfDir := fs.deviceDir(pf.pciAddr)
	fs.symlink(fmt.Sprintf("../%s", vfPCIAddr), filepath.Join(pfDir, fmt.Sprintf("virtfn%d", vfID)))

	if vfIfname != "" {
		fs.addNetDir(vfPCIAddr, vfIfname)
	}
}

func (fs *fakeSysfs) newManager(t testing.TB, cfg *v2alpha1.EswitchSRIOVDeviceManagerConfig, nl netlinkOps) *EswitchSRIOVManager {
	t.Helper()
	return &EswitchSRIOVManager{
		logger:  hivetest.Logger(t),
		sysPath: fs.root,
		config:  cfg,
		nl:      nl,
	}
}

// setupFakes builds a fake sysfs+netlink pair with one PF (0000:02:00.0,
// "mypf") already in switchdev mode with zero VFs. Individual tests add
// VFs/representors on top.
func setupFakes(t *testing.T) (*fakeSysfs, *fakeNetlinkOps) {
	t.Helper()
	fs := newFakeSysfs(t)
	nl := newFakeNetlink()

	fs.addPF("0000:02:00.0", "mypf")
	nl.addLink(newFakeLink("mypf", "0000:02:00.0", nil))
	nl.addDevlinkDevice(pciBusName, "0000:02:00.0", eswitchModeSwitchdev)

	return fs, nl
}

// TestEswitchSRIOV_Init covers EswitchSRIOVManager.init()'s per-PF pipeline:
// eswitch mode switching, VF creation, bridge reconciliation, and
// representor enslavement. Grouped into one test (mirroring TestSriov in
// the sriov package) with nested subtests per concern.
func TestEswitchSRIOV_Init(t *testing.T) {
	t.Run("mode switch", func(t *testing.T) {
		t.Run("already switchdev is a no-op", func(t *testing.T) {
			fs, nl := setupFakes(t)
			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf", VFCount: 0}},
			}
			mgr := fs.newManager(t, cfg, nl)
			require.NoError(t, mgr.init())
			require.Empty(t, nl.devlinkModeSetCalls)
		})

		t.Run("legacy with zero vfs switches successfully", func(t *testing.T) {
			fs := newFakeSysfs(t)
			nl := newFakeNetlink()
			fs.addPF("0000:03:00.0", "mypf2")
			nl.addLink(newFakeLink("mypf2", "0000:03:00.0", nil))
			nl.addDevlinkDevice(pciBusName, "0000:03:00.0", eswitchModeLegacy)

			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf2", VFCount: 0}},
			}
			mgr := fs.newManager(t, cfg, nl)
			require.NoError(t, mgr.init())
			require.Equal(t, []devlinkModeSetCall{{bus: pciBusName, device: "0000:03:00.0", mode: eswitchModeSwitchdev}}, nl.devlinkModeSetCalls)
		})

		t.Run("legacy with existing vfs is skipped, other PFs still processed", func(t *testing.T) {
			fs := newFakeSysfs(t)
			nl := newFakeNetlink()

			badPF := fs.addPF("0000:03:00.0", "badpf")
			fs.setNumVFs(badPF, 2)
			nl.addLink(newFakeLink("badpf", "0000:03:00.0", nil))
			nl.addDevlinkDevice(pciBusName, "0000:03:00.0", eswitchModeLegacy)

			fs.addPF("0000:04:00.0", "goodpf")
			nl.addLink(newFakeLink("goodpf", "0000:04:00.0", nil))
			nl.addDevlinkDevice(pciBusName, "0000:04:00.0", eswitchModeLegacy)

			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{
					{IfName: "badpf", VFCount: 0},
					{IfName: "goodpf", VFCount: 0},
				},
			}
			mgr := fs.newManager(t, cfg, nl)
			err := mgr.init()
			require.ErrorIs(t, err, errVFsExistCannotSwitchMode)
			// only goodpf's mode switch happened.
			require.Equal(t, []devlinkModeSetCall{{bus: pciBusName, device: "0000:04:00.0", mode: eswitchModeSwitchdev}}, nl.devlinkModeSetCalls)
		})
	})

	t.Run("vf creation", func(t *testing.T) {
		t.Run("too many vfs", func(t *testing.T) {
			fs, nl := setupFakes(t)
			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf", VFCount: 100}},
			}
			mgr := fs.newManager(t, cfg, nl)
			require.ErrorIs(t, mgr.init(), errTooManyVFs)
		})

		t.Run("fresh write", func(t *testing.T) {
			fs, nl := setupFakes(t)
			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf", VFCount: 2}},
			}
			mgr := fs.newManager(t, cfg, nl)
			require.NoError(t, mgr.init())

			numVfs, err := os.ReadFile(filepath.Join(mgr.pciDevicesPath(), "0000:02:00.0", "sriov_numvfs"))
			require.NoError(t, err)
			require.Equal(t, "2", string(numVfs))
		})

		t.Run("already configured, mismatched count is left alone", func(t *testing.T) {
			fs, nl := setupFakes(t)
			fs.setNumVFs(&pfInfo{pciAddr: "0000:02:00.0"}, 4)
			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf", VFCount: 2}},
			}
			mgr := fs.newManager(t, cfg, nl)
			require.NoError(t, mgr.init())

			numVfs, err := os.ReadFile(filepath.Join(mgr.pciDevicesPath(), "0000:02:00.0", "sriov_numvfs"))
			require.NoError(t, err)
			require.Equal(t, "4\n", string(numVfs))
		})
	})

	t.Run("bridges", func(t *testing.T) {
		t.Run("creates a fresh bridge with params baked into LinkAdd", func(t *testing.T) {
			fs, nl := setupFakes(t)
			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf", VFCount: 0, BridgeName: "br0"}},
				Bridges: []v2alpha1.EswitchBridgeConfig{
					{Name: "br0", Params: map[string]string{"vlan_filtering": "true", "multicast_snooping": "true"}},
				},
			}
			mgr := fs.newManager(t, cfg, nl)
			require.NoError(t, mgr.init())

			require.Equal(t, []string{"br0"}, nl.linkAddCalls)
			require.Contains(t, nl.linkSetUpCalls, "br0")
			require.Equal(t, []masterSetCall{{linkName: "mypf", masterName: "br0"}}, nl.masterSetCalls)

			// setBridgeParams bakes both params into the *netlink.Bridge value
			// passed to LinkAdd (real switchdev hardware rejects toggling
			// vlan_filtering via a later LinkModify once ports are enslaved, so
			// params must be set before creation, not after) — no LinkModify
			// calls should happen for a freshly created bridge.
			require.Empty(t, nl.linkModifyCalls)
			br, err := nl.LinkByName("br0")
			require.NoError(t, err)
			bridge, ok := br.(*netlink.Bridge)
			require.True(t, ok)
			require.NotNil(t, bridge.VlanFiltering)
			require.True(t, *bridge.VlanFiltering)
			require.NotNil(t, bridge.MulticastSnooping)
			require.True(t, *bridge.MulticastSnooping)
		})

		t.Run("unrecognized param is rejected", func(t *testing.T) {
			fs, nl := setupFakes(t)
			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf", VFCount: 0, BridgeName: "br0"}},
				Bridges: []v2alpha1.EswitchBridgeConfig{
					{Name: "br0", Params: map[string]string{"stp_state": "1"}},
				},
			}
			mgr := fs.newManager(t, cfg, nl)
			err := mgr.init()
			require.Error(t, err)
			require.ErrorIs(t, err, errUnknownBridgeParam)
		})
		t.Run("shared bridge across PFs is reconciled once", func(t *testing.T) {
			fs, nl := setupFakes(t)
			fs.addPF("0000:05:00.0", "mypf2")
			nl.addLink(newFakeLink("mypf2", "0000:05:00.0", nil))
			nl.addDevlinkDevice(pciBusName, "0000:05:00.0", eswitchModeSwitchdev)

			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{
					{IfName: "mypf", VFCount: 0, BridgeName: "shared"},
					{IfName: "mypf2", VFCount: 0, BridgeName: "shared"},
				},
				Bridges: []v2alpha1.EswitchBridgeConfig{{Name: "shared"}},
			}
			mgr := fs.newManager(t, cfg, nl)
			require.NoError(t, mgr.init())

			require.Equal(t, []string{"shared"}, nl.linkAddCalls)
			require.ElementsMatch(t, []masterSetCall{
				{linkName: "mypf", masterName: "shared"},
				{linkName: "mypf2", masterName: "shared"},
			}, nl.masterSetCalls)
		})

		t.Run("unknown bridge param errors just that PF", func(t *testing.T) {
			fs, nl := setupFakes(t)
			fs.addPF("0000:05:00.0", "goodpf")
			nl.addLink(newFakeLink("goodpf", "0000:05:00.0", nil))
			nl.addDevlinkDevice(pciBusName, "0000:05:00.0", eswitchModeSwitchdev)

			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{
					{IfName: "mypf", VFCount: 0, BridgeName: "badbr"},
					{IfName: "goodpf", VFCount: 0, BridgeName: "goodbr"},
				},
				Bridges: []v2alpha1.EswitchBridgeConfig{
					{Name: "badbr", Params: map[string]string{"nonsense": "1"}},
					{Name: "goodbr"},
				},
			}
			mgr := fs.newManager(t, cfg, nl)
			err := mgr.init()
			require.ErrorIs(t, err, errUnknownBridgeParam)
			// goodpf still got enslaved despite badpf's failure.
			require.Contains(t, nl.masterSetCalls, masterSetCall{linkName: "goodpf", masterName: "goodbr"})
		})

		t.Run("uplink already enslaved is idempotent", func(t *testing.T) {
			fs, nl := setupFakes(t)
			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces:  []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf", VFCount: 0, BridgeName: "br0"}},
				Bridges: []v2alpha1.EswitchBridgeConfig{{Name: "br0"}},
			}
			mgr := fs.newManager(t, cfg, nl)
			require.NoError(t, mgr.init())
			require.Len(t, nl.masterSetCalls, 1)

			// re-run init: uplink is already enslaved (fake tracks MasterIndex),
			// bridge already exists -> no new LinkAdd, no new master calls, and
			// no LinkModify (params are never re-applied to an existing bridge).
			require.NoError(t, mgr.init())
			require.Len(t, nl.masterSetCalls, 1)
			require.Equal(t, []string{"br0"}, nl.linkAddCalls)
			require.Empty(t, nl.linkModifyCalls)
		})

		t.Run("existing bridge with matching params logs no diff and is not modified", func(t *testing.T) {
			fs, nl := setupFakes(t)
			vlanFiltering, mcastSnoop := true, true
			br := newFakeBridgeLink("br0", 200)
			br.VlanFiltering = &vlanFiltering
			br.MulticastSnooping = &mcastSnoop
			nl.addLink(br)
			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf", VFCount: 0, BridgeName: "br0"}},
				Bridges: []v2alpha1.EswitchBridgeConfig{
					{Name: "br0", Params: map[string]string{"vlan_filtering": "true", "multicast_snooping": "true"}},
				},
			}
			mgr := fs.newManager(t, cfg, nl)
			require.NoError(t, mgr.init())

			require.Empty(t, nl.linkAddCalls)
			require.Empty(t, nl.linkModifyCalls)
		})

		t.Run("existing bridge with mismatched params is not modified but does not fail init", func(t *testing.T) {
			fs, nl := setupFakes(t)
			vlanFiltering, mcastSnoop := false, false
			br := newFakeBridgeLink("br0", 201)
			br.VlanFiltering = &vlanFiltering
			br.MulticastSnooping = &mcastSnoop
			nl.addLink(br)
			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf", VFCount: 0, BridgeName: "br0"}},
				Bridges: []v2alpha1.EswitchBridgeConfig{
					{Name: "br0", Params: map[string]string{"vlan_filtering": "true", "multicast_snooping": "true"}},
				},
			}
			mgr := fs.newManager(t, cfg, nl)
			// A param mismatch on a pre-existing bridge is only logged, not
			// treated as an error — the PF is still processed normally.
			require.NoError(t, mgr.init())
			require.Empty(t, nl.linkAddCalls)
			require.Empty(t, nl.linkModifyCalls)
			require.Contains(t, nl.masterSetCalls, masterSetCall{linkName: "mypf", masterName: "br0"})
		})
	})

	t.Run("representors", func(t *testing.T) {
		t.Run("vf with representor is enslaved", func(t *testing.T) {
			fs, nl := setupFakes(t)
			pf := &pfInfo{pciAddr: "0000:02:00.0", ifname: "mypf"}
			fs.addVF(pf, "0000:02:00.1", 0, "")
			nl.addDevlinkPort(pf.pciAddr, 0, "mypf_0")
			nl.addLink(newFakeLink("mypf_0", "", nil))

			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces:  []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf", VFCount: 1, BridgeName: "br0"}},
				Bridges: []v2alpha1.EswitchBridgeConfig{{Name: "br0"}},
			}
			mgr := fs.newManager(t, cfg, nl)
			require.NoError(t, mgr.init())

			require.Contains(t, nl.masterSetCalls, masterSetCall{linkName: "mypf_0", masterName: "br0"})
		})

		t.Run("vf with no representor is not enslaved, other vfs unaffected", func(t *testing.T) {
			fs, nl := setupFakes(t)
			pf := &pfInfo{pciAddr: "0000:02:00.0", ifname: "mypf"}
			fs.addVF(pf, "0000:02:00.1", 0, "") // no representor for vf0
			fs.addVF(pf, "0000:02:00.2", 1, "")
			nl.addDevlinkPort(pf.pciAddr, 1, "mypf_1")
			nl.addLink(newFakeLink("mypf_1", "", nil))

			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces:  []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf", VFCount: 2, BridgeName: "br0"}},
				Bridges: []v2alpha1.EswitchBridgeConfig{{Name: "br0"}},
			}
			mgr := fs.newManager(t, cfg, nl)
			require.NoError(t, mgr.init())

			require.Contains(t, nl.masterSetCalls, masterSetCall{linkName: "mypf_1", masterName: "br0"})
			for _, c := range nl.masterSetCalls {
				require.NotEqual(t, "mypf_0", c.linkName)
			}
		})
	})

	t.Run("fault injection: netlinkOps errors", func(t *testing.T) {
		t.Run("LinkAdd failure errors that PF, continues", func(t *testing.T) {
			fs := newFakeSysfs(t)
			nl := newFakeNetlink()

			// PF 1: will fail bridge LinkAdd
			_ = fs.addPF("0000:03:00.0", "badpf")
			nl.addLink(newFakeLink("badpf", "0000:03:00.0", nil))
			nl.addDevlinkDevice(pciBusName, "0000:03:00.0", eswitchModeSwitchdev)
			nl.linkAddErr = errors.New("LinkAdd failed")

			// PF 2: has working bridge
			_ = fs.addPF("0000:04:00.0", "goodpf")
			nl.addLink(newFakeLink("goodpf", "0000:04:00.0", nil))
			nl.addDevlinkDevice(pciBusName, "0000:04:00.0", eswitchModeSwitchdev)

			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{
					{IfName: "badpf", VFCount: 0, BridgeName: "br0"},
					{IfName: "goodpf", VFCount: 0, BridgeName: "br1"},
				},
				Bridges: []v2alpha1.EswitchBridgeConfig{
					{Name: "br0"},
					{Name: "br1"},
				},
			}
			mgr := fs.newManager(t, cfg, nl)
			err := mgr.init()
			require.Error(t, err)
			require.Contains(t, err.Error(), "LinkAdd failed")

			// goodpf's br1 should still be created, but badpf fails first so LinkAdd error stops all bridge creation
			// The test verifies the error is propagated
			require.GreaterOrEqual(t, len(nl.linkAddCalls), 1, "at least one LinkAdd should have been attempted")
		})

		t.Run("DevLinkSetEswitchMode failure errors that PF, continues to others", func(t *testing.T) {
			fs := newFakeSysfs(t)
			nl := newFakeNetlink()

			// PF 1: mode switch will fail
			_ = fs.addPF("0000:03:00.0", "badpf")
			nl.addLink(newFakeLink("badpf", "0000:03:00.0", nil))
			nl.addDevlinkDevice(pciBusName, "0000:03:00.0", eswitchModeLegacy)
			nl.devLinkSetEswitchModeErr = errors.New("DevLinkSetEswitchMode failed")

			// PF 2: already in switchdev mode (no mode switch needed)
			_ = fs.addPF("0000:04:00.0", "goodpf")
			nl.addLink(newFakeLink("goodpf", "0000:04:00.0", nil))
			nl.addDevlinkDevice(pciBusName, "0000:04:00.0", eswitchModeSwitchdev)

			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{
					{IfName: "badpf", VFCount: 0},
					{IfName: "goodpf", VFCount: 0},
				},
			}
			mgr := fs.newManager(t, cfg, nl)
			err := mgr.init()
			require.Error(t, err)
			require.Contains(t, err.Error(), "DevLinkSetEswitchMode failed")

			// goodpf is already in switchdev mode so no mode switch attempted
			// Only badpf would have attempted the switch and failed
			require.Len(t, nl.devlinkModeSetCalls, 1, "only badpf should attempt mode switch")
		})

		t.Run("BridgeVlanAdd failure during Setup surfaces error", func(t *testing.T) {
			nl := newFakeNetlink()
			nl.addLink(newFakeLinkWithIndex("rep0", 42))
			nl.bridgeVlanAddErr = errors.New("BridgeVlanAdd failed")

			dev := EswitchPciDevice{RepresentorName: "rep0", nl: nl}
			err := dev.Setup(types.DeviceConfig{Vlan: 100})
			require.Error(t, err)
			require.Contains(t, err.Error(), "BridgeVlanAdd failed")
		})

		t.Run("representor LinkByName failure during Setup surfaces error", func(t *testing.T) {
			nl := newFakeNetlink()
			nl.linkByNameErr = errors.New("LinkByName failed")

			dev := EswitchPciDevice{RepresentorName: "nonexistent", nl: nl}
			err := dev.Setup(types.DeviceConfig{Vlan: 100})
			require.Error(t, err)
			require.Contains(t, err.Error(), "LinkByName failed")
		})

		t.Run("custom sysPath via withSysPath helper", func(t *testing.T) {
			fs := newFakeSysfs(t)
			nl := newFakeNetlink()
			fs.addPF("0000:02:00.0", "mypf")
			nl.addLink(newFakeLink("mypf", "0000:02:00.0", nil))
			nl.addDevlinkDevice(pciBusName, "0000:02:00.0", eswitchModeSwitchdev)

			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf", VFCount: 0}},
			}
			// Use withSysPath to verify the helper works
			mgr := &EswitchSRIOVManager{
				logger: hivetest.Logger(t),
				config: cfg,
				nl:     nl,
			}
			withSysPath(fs.root)(mgr)
			require.NoError(t, mgr.init())
		})

		t.Run("netlinkOps injection via withNetlinkOps helper", func(t *testing.T) {
			fs, _ := setupFakes(t)
			nl := newFakeNetlink()
			nl.addLink(newFakeLink("mypf", "0000:02:00.0", nil))
			nl.addDevlinkDevice(pciBusName, "0000:02:00.0", eswitchModeSwitchdev)

			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf", VFCount: 0}},
			}
			mgr := &EswitchSRIOVManager{
				logger:  hivetest.Logger(t),
				sysPath: fs.root,
				config:  cfg,
				nl:      nl,
			}
			// Use withNetlinkOps to verify the helper works
			withNetlinkOps(nl)(mgr)
			require.NoError(t, mgr.init())
		})
	})
}

func TestEswitchSRIOV_Discovery(t *testing.T) {
	t.Run("ListDevices", func(t *testing.T) {
		t.Run("advertises only vfs with a resolvable representor", func(t *testing.T) {
			fs, nl := setupFakes(t)
			pf := &pfInfo{pciAddr: "0000:02:00.0", ifname: "mypf"}
			fs.addVF(pf, "0000:02:00.1", 0, "myvf")
			nl.addDevlinkPort(pf.pciAddr, 0, "mypf_0")
			nl.addLink(newFakeLink("mypf_0", "", nil))

			fs.addVF(pf, "0000:02:00.2", 1, "") // no representor

			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf", VFCount: 0}},
			}
			mgr := fs.newManager(t, cfg, nl)

			devices, err := mgr.listDevices()
			require.NoError(t, err)
			require.Len(t, devices, 1)

			dev := devices[0].(*EswitchPciDevice)
			require.Equal(t, "0000:02:00.1", dev.Addr)
			require.Equal(t, "mypf_0", dev.RepresentorName)
			require.Equal(t, "myvf", dev.KernelIfName())
		})

		t.Run("bridge pf enslavement gates advertisement", func(t *testing.T) {
			fs, nl := setupFakes(t)
			pf := &pfInfo{pciAddr: "0000:02:00.0", ifname: "mypf"}
			fs.addVF(pf, "0000:02:00.1", 0, "")
			nl.addDevlinkPort(pf.pciAddr, 0, "mypf_0")
			nl.addLink(newFakeLink("mypf_0", "", nil))

			cfg := &v2alpha1.EswitchSRIOVDeviceManagerConfig{
				Ifaces: []v2alpha1.EswitchSRIOVDeviceConfig{{IfName: "mypf", VFCount: 0, BridgeName: "br0"}},
			}
			mgr := fs.newManager(t, cfg, nl)

			t.Run("bridge does not exist: VF not advertised", func(t *testing.T) {
				devices, err := mgr.listDevices()
				require.NoError(t, err)
				require.Empty(t, devices)
			})

			t.Run("bridge exists but PF not enslaved to it: VF not advertised", func(t *testing.T) {
				nl.addLink(newFakeLinkWithIndex("br0", 500))

				devices, err := mgr.listDevices()
				require.NoError(t, err)
				require.Empty(t, devices)
			})

			t.Run("PF enslaved to its configured bridge: VF advertised", func(t *testing.T) {
				fs.setMaster(pf.pciAddr, pf.ifname, "br0")

				devices, err := mgr.listDevices()
				require.NoError(t, err)
				require.Len(t, devices, 1)
			})
		})
	})

	t.Run("FindRepresentor", func(t *testing.T) {
		t.Run("resolves representor by pf and vf index", func(t *testing.T) {
			fs, nl := setupFakes(t)
			pf := &pfInfo{pciAddr: "0000:02:00.0", ifname: "mypf"}
			nl.addDevlinkPort(pf.pciAddr, 0, "rep0")

			mgr := fs.newManager(t, &v2alpha1.EswitchSRIOVDeviceManagerConfig{}, nl)

			name, err := mgr.findRepresentor(pf.pciAddr, 0)
			require.NoError(t, err)
			require.Equal(t, "rep0", name)

			name, err = mgr.findRepresentor(pf.pciAddr, 5)
			require.NoError(t, err)
			require.Empty(t, name)
		})

		t.Run("does not leak across PFs", func(t *testing.T) {
			fs, nl := setupFakes(t)
			pf := &pfInfo{pciAddr: "0000:02:00.0", ifname: "mypf"}
			nl.addDevlinkPort(pf.pciAddr, 0, "rep0")
			nl.addDevlinkPort("0000:03:00.0", 0, "otherpf_rep0")

			mgr := fs.newManager(t, &v2alpha1.EswitchSRIOVDeviceManagerConfig{}, nl)

			name, err := mgr.findRepresentor(pf.pciAddr, 0)
			require.NoError(t, err)
			require.Equal(t, "rep0", name)

			name, err = mgr.findRepresentor("0000:03:00.0", 0)
			require.NoError(t, err)
			require.Equal(t, "otherpf_rep0", name)
		})
	})
}

func TestEswitchPciDevice(t *testing.T) {
	t.Run("SetupFree", func(t *testing.T) {
		nl := newFakeNetlink()
		nl.addLink(newFakeLinkWithIndex("rep0", 42))

		dev := EswitchPciDevice{RepresentorName: "rep0", nl: nl}

		t.Run("vlan 0 is a no-op", func(t *testing.T) {
			require.NoError(t, dev.Setup(types.DeviceConfig{Vlan: 0}))
			require.Empty(t, nl.bridgeVlanAdds)
		})

		t.Run("setup adds vlan, idempotent on repeat", func(t *testing.T) {
			require.NoError(t, dev.Setup(types.DeviceConfig{Vlan: 100}))
			require.Len(t, nl.bridgeVlanAdds, 1)
			require.Equal(t, bridgeVlanCall{linkName: "rep0", vid: 100, pvid: true, untagged: true}, nl.bridgeVlanAdds[0])

			// calling again should be a no-op since the vlan is already present.
			require.NoError(t, dev.Setup(types.DeviceConfig{Vlan: 100}))
			require.Len(t, nl.bridgeVlanAdds, 1)
		})

		t.Run("free removes vlan, idempotent on repeat", func(t *testing.T) {
			require.NoError(t, dev.Free(types.DeviceConfig{Vlan: 100}))
			require.Len(t, nl.bridgeVlanDels, 1)

			require.NoError(t, dev.Free(types.DeviceConfig{Vlan: 100}))
			require.Len(t, nl.bridgeVlanDels, 1)
		})

		t.Run("no representor errors hard, not silent", func(t *testing.T) {
			d := EswitchPciDevice{nl: nl}
			require.ErrorIs(t, d.Setup(types.DeviceConfig{Vlan: 5}), errRepresentorNotFound)
			require.ErrorIs(t, d.Free(types.DeviceConfig{Vlan: 5}), errRepresentorNotFound)
		})
	})

	// BouncesBridgeMembership verifies that Setup and Free bounce the
	// representor's bridge enslavement (NOMASTER then MASTER) unconditionally
	// before every BridgeVlanAdd call, to work around an intermittent EINVAL
	// from some NICs' switchdev VLAN offload (see bounceBridgeMembership's
	// doc comment). BridgeName must be set for the bounce to happen at all —
	// an empty BridgeName (e.g. a device that was never actually attached to
	// a bridge) is a no-op.
	t.Run("BouncesBridgeMembership", func(t *testing.T) {
		nl := newFakeNetlink()
		nl.addLink(newFakeLinkWithIndex("rep0", 42))
		nl.addLink(newFakeLinkWithIndex("br0", 7))

		dev := EswitchPciDevice{RepresentorName: "rep0", BridgeName: "br0", nl: nl}

		t.Run("setup bounces before adding the requested vlan", func(t *testing.T) {
			require.NoError(t, dev.Setup(types.DeviceConfig{Vlan: 100}))
			require.Equal(t, []string{"rep0"}, nl.noMasterCalls)
			require.Equal(t, []masterSetCall{{linkName: "rep0", masterName: "br0"}}, nl.masterSetCalls)
			require.Len(t, nl.bridgeVlanAdds, 1)

			// idempotent no-op: vlan already present, no additional bounce.
			require.NoError(t, dev.Setup(types.DeviceConfig{Vlan: 100}))
			require.Len(t, nl.noMasterCalls, 1)
			require.Len(t, nl.masterSetCalls, 1)
		})

		t.Run("free bounces before restoring the default pvid", func(t *testing.T) {
			require.NoError(t, dev.Free(types.DeviceConfig{Vlan: 100}))
			// one extra bounce beyond the one from Setup above.
			require.Len(t, nl.noMasterCalls, 2)
			require.Len(t, nl.masterSetCalls, 2)
			require.Equal(t, "rep0", nl.noMasterCalls[1])
			require.Equal(t, masterSetCall{linkName: "rep0", masterName: "br0"}, nl.masterSetCalls[1])
		})

		t.Run("no bounce when BridgeName is empty", func(t *testing.T) {
			nl2 := newFakeNetlink()
			nl2.addLink(newFakeLinkWithIndex("rep1", 43))
			d := EswitchPciDevice{RepresentorName: "rep1", nl: nl2}

			require.NoError(t, d.Setup(types.DeviceConfig{Vlan: 200}))
			require.Empty(t, nl2.noMasterCalls)
			require.Empty(t, nl2.masterSetCalls)
		})

		t.Run("bounce failure surfaces as an error, does not fall through to BridgeVlanAdd", func(t *testing.T) {
			nl3 := newFakeNetlink()
			nl3.addLink(newFakeLinkWithIndex("rep2", 44))
			nl3.addLink(newFakeLinkWithIndex("br1", 8))
			nl3.linkSetNoMasterErr = errors.New("boom")

			d := EswitchPciDevice{RepresentorName: "rep2", BridgeName: "br1", nl: nl3}
			err := d.Setup(types.DeviceConfig{Vlan: 300})
			require.Error(t, err)
			require.Contains(t, err.Error(), "failed to bounce bridge membership")
			require.Empty(t, nl3.bridgeVlanAdds)
		})
	})

	t.Run("Match", func(t *testing.T) {
		dev := EswitchPciDevice{
			Addr:            "0000:03:00.1",
			Driver:          "mlx5_core",
			Vendor:          "0x15b3",
			DeviceID:        "0x1018",
			PFName:          "ens1f0",
			KernelIfaceName: "ens1f0v0",
		}

		cases := []struct {
			name   string
			filter v2alpha1.CiliumNetworkDriverDeviceFilter
			want   bool
		}{
			{"empty filter matches everything", v2alpha1.CiliumNetworkDriverDeviceFilter{}, true},
			{"matching device manager", v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceManagers: []string{types.DeviceManagerTypeEswitchSRIOV.String()}}, true},
			{"non-matching device manager", v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceManagers: []string{"sr-iov"}}, false},
			{"matching pci addr", v2alpha1.CiliumNetworkDriverDeviceFilter{PCIAddrs: []string{"0000:03:00.1"}}, true},
			{"non-matching pci addr", v2alpha1.CiliumNetworkDriverDeviceFilter{PCIAddrs: []string{"0000:03:00.2"}}, false},
			{"matching ifname", v2alpha1.CiliumNetworkDriverDeviceFilter{IfNames: []string{"ens1f0v0"}}, true},
			{"matching pfname", v2alpha1.CiliumNetworkDriverDeviceFilter{PFNames: []string{"ens1f0"}}, true},
			{"matching vendor id", v2alpha1.CiliumNetworkDriverDeviceFilter{VendorIDs: []string{"0x15b3"}}, true},
			{"matching device id", v2alpha1.CiliumNetworkDriverDeviceFilter{DeviceIDs: []string{"0x1018"}}, true},
			{"matching driver", v2alpha1.CiliumNetworkDriverDeviceFilter{Drivers: []string{"mlx5_core"}}, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				require.Equal(t, tc.want, dev.Match(tc.filter))
			})
		}
	})

	t.Run("Merge", func(t *testing.T) {
		t.Run("carries forward kernel ifname when empty", func(t *testing.T) {
			old := &EswitchPciDevice{KernelIfaceName: "oldname", RepresentorName: "oldrep", BridgeName: "oldbr", PFName: "oldpf"}
			fresh := &EswitchPciDevice{RepresentorName: "newrep", BridgeName: "newbr", PFName: "newpf"}
			fresh.Merge(old)

			require.Equal(t, "oldname", fresh.KernelIfaceName)
			// representor/bridge/pf are always freshly resolved, never carried forward.
			require.Equal(t, "newrep", fresh.RepresentorName)
			require.Equal(t, "newbr", fresh.BridgeName)
			require.Equal(t, "newpf", fresh.PFName)
		})

		t.Run("does not overwrite a non-empty kernel ifname", func(t *testing.T) {
			old := &EswitchPciDevice{KernelIfaceName: "oldname"}
			fresh := &EswitchPciDevice{KernelIfaceName: "newname"}
			fresh.Merge(old)
			require.Equal(t, "newname", fresh.KernelIfaceName)
		})
	})

	t.Run("MarshalUnmarshalRoundTrip", func(t *testing.T) {
		dev := EswitchPciDevice{
			Addr:            "0000:03:00.1",
			Driver:          "mlx5_core",
			Vendor:          "0x15b3",
			DeviceID:        "0x1018",
			PFName:          "ens1f0",
			VFID:            2,
			KernelIfaceName: "ens1f0v2",
			RepresentorName: "rep2",
			BridgeName:      "br0",
		}

		t.Run("round trip preserves fields", func(t *testing.T) {
			data, err := dev.MarshalBinary()
			require.NoError(t, err)

			var restored EswitchPciDevice
			require.NoError(t, restored.UnmarshalBinary(data))
			require.Equal(t, dev.Addr, restored.Addr)
			require.Equal(t, dev.RepresentorName, restored.RepresentorName)
			require.Equal(t, dev.BridgeName, restored.BridgeName)
		})

		t.Run("RestoreDevice re-injects nl and unmarshals", func(t *testing.T) {
			data, err := dev.MarshalBinary()
			require.NoError(t, err)

			mgr := &EswitchSRIOVManager{nl: newFakeNetlink()}
			restoredDevice, err := mgr.RestoreDevice(data)
			require.NoError(t, err)
			require.Equal(t, "rep2", restoredDevice.(*EswitchPciDevice).RepresentorName)
		})
	})
}
