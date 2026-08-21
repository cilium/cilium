// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package eswitch_sriov implements a device manager for SR-IOV VFs on NICs
// running in eswitch/switchdev offload mode (e.g. Mellanox/NVIDIA ConnectX).
//
// In switchdev mode, VF traffic isolation (VLANs, etc.) cannot be enforced
// via ndo_set_vf_vlan (switchdev-mode NICs typically reject this for
// non-zero VLANs). Instead, each VF is represented on the host by a
// "representor" netdev that always stays in the root namespace even after
// the VF itself is moved into a pod's network namespace. Isolation is
// enforced by attaching PF uplinks and VF representors to a Linux bridge and
// programming VLAN membership on the bridge ports (BridgeVlanAdd/Del).
package eswitch_sriov

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

const (
	defaultSysfsPath = "/host/sys"
	pciDevicesPath   = "bus/pci/devices"

	pciBusName = "pci"

	eswitchModeLegacy    = "legacy"
	eswitchModeSwitchdev = "switchdev"

	// defaultBridgeVID is the VLAN a port is automatically made a PVID+
	// untagged member of the moment it is enslaved to a VLAN-filtering
	// bridge (kernel default). A bridge port can only ever have one PVID
	// at a time, so before Setup can install the pod-requested VLAN as
	// this port's new PVID, defaultBridgeVID's PVID flag must first be
	// cleared (demoted to a plain untagged member) — the kernel rejects
	// BridgeVlanAdd for a second PVID with EINVAL otherwise. Free reverses
	// this: once the pod-requested VLAN is removed, defaultBridgeVID is
	// restored as PVID+untagged so the port initial state is restored fully.
	defaultBridgeVID = 1
)

var (
	errNotAVF                   = errors.New("device is not a vf")
	errTooManyVFs               = errors.New("too many vfs")
	errInterfaceNotFound        = errors.New("interface not found")
	errVFIDNotFound             = errors.New("could not find VF ID")
	errRepresentorNotFound      = errors.New("vf representor not found")
	errBridgeReconcile          = errors.New("failed to reconcile bridge")
	errUnknownBridgeParam       = errors.New("unknown bridge parameter")
	errVFsExistCannotSwitchMode = errors.New("cannot switch eswitch mode: vfs already exist on pf")
	errDevlinkDeviceNotFound    = errors.New("devlink device not found for pf")
)

// netlinkOps abstracts the netlink/devlink mutation calls used by
// EswitchSRIOVManager and EswitchPciDevice.
// netlinkOps is reserved for operations with no sysfs
// equivalent: creating/modifying links, attaching devices to a bridge,
// programming bridge VLAN membership, switching devlink eswitch mode, and
// listing devlink ports/devices. The real implementation delegates to
// safenetlink/netlink; tests inject a fake.
type netlinkOps interface {
	// LinkByName returns the link with the given interface name.
	LinkByName(name string) (netlink.Link, error)
	// LinkAdd creates a new link (used to create bridges).
	LinkAdd(link netlink.Link) error
	// LinkModify updates an existing link's attributes (used to reconcile
	// bridge parameters).
	LinkModify(link netlink.Link) error
	// LinkSetUp brings a link up.
	LinkSetUp(link netlink.Link) error
	// LinkSetMaster attaches link to master (used to attach uplinks/
	// representors to a bridge).
	LinkSetMaster(link, master netlink.Link) error
	// LinkSetNoMaster detaches link from its current bridge master. Used
	// together with LinkSetMaster to "bounce" a representor's bridge
	// enslavement immediately before a BridgeVlanAdd call — see the
	// bounceBridgeMembership doc comment for why this is necessary.
	LinkSetNoMaster(link netlink.Link) error
	// BridgeVlanAdd adds a VLAN to a bridge port.
	BridgeVlanAdd(link netlink.Link, vid uint16, pvid, untagged, self, master bool) error
	// BridgeVlanDel removes a VLAN from a bridge port.
	BridgeVlanDel(link netlink.Link, vid uint16, pvid, untagged, self, master bool) error
	// BridgeVlanList returns the current bridge VLAN table, keyed by link
	// ifindex. Used as the source of truth for idempotent Setup/Free.
	BridgeVlanList() (map[int32][]*nl.BridgeVlanInfo, error)
	// DevLinkGetDeviceList lists all devlink devices, used to read/verify
	// eswitch mode.
	DevLinkGetDeviceList() ([]*netlink.DevlinkDevice, error)
	// DevLinkSetEswitchMode sets the eswitch mode ("legacy"/"switchdev")
	// for a devlink device.
	DevLinkSetEswitchMode(dev *netlink.DevlinkDevice, newMode string) error
	// DevLinkGetAllPortList lists all devlink ports across all devices, used
	// to resolve a VF's representor netdev by PF/VF number.
	DevLinkGetAllPortList() ([]*netlink.DevlinkPort, error)
}

const (
	bridgeVlanInfoPVID     = 1 << 1
	bridgeVlanInfoUntagged = 1 << 2
)

// netlinkImpl delegates to the production safenetlink/netlink implementations.
type netlinkImpl struct{}

func (netlinkImpl) LinkByName(name string) (netlink.Link, error) {
	return safenetlink.LinkByName(name)
}

func (netlinkImpl) LinkAdd(link netlink.Link) error {
	return netlink.LinkAdd(link)
}

func (netlinkImpl) LinkModify(link netlink.Link) error {
	return netlink.LinkModify(link)
}

func (netlinkImpl) LinkSetUp(link netlink.Link) error {
	return netlink.LinkSetUp(link)
}

func (netlinkImpl) LinkSetMaster(link, master netlink.Link) error {
	return netlink.LinkSetMaster(link, master)
}

func (netlinkImpl) LinkSetNoMaster(link netlink.Link) error {
	return netlink.LinkSetNoMaster(link)
}

func (netlinkImpl) BridgeVlanAdd(link netlink.Link, vid uint16, pvid, untagged, self, master bool) error {
	return netlink.BridgeVlanAdd(link, vid, pvid, untagged, self, master)
}

func (netlinkImpl) BridgeVlanDel(link netlink.Link, vid uint16, pvid, untagged, self, master bool) error {
	return netlink.BridgeVlanDel(link, vid, pvid, untagged, self, master)
}

func (netlinkImpl) BridgeVlanList() (map[int32][]*nl.BridgeVlanInfo, error) {
	return safenetlink.BridgeVlanList()
}

func (netlinkImpl) DevLinkGetDeviceList() ([]*netlink.DevlinkDevice, error) {
	return safenetlink.DevLinkGetDeviceList()
}

func (netlinkImpl) DevLinkSetEswitchMode(dev *netlink.DevlinkDevice, newMode string) error {
	return netlink.DevLinkSetEswitchMode(dev, newMode)
}

func (netlinkImpl) DevLinkGetAllPortList() ([]*netlink.DevlinkPort, error) {
	return safenetlink.DevLinkGetAllPortList()
}

// EswitchPciDevice represents a single SR-IOV VF managed via its host-side
// representor netdev.
type EswitchPciDevice struct {
	Addr            string // VF PCI address
	Driver          string
	Vendor          string
	DeviceID        string
	PFName          string // PF kernel ifname
	VFID            int
	KernelIfaceName string // VF's own kernel ifname, if any (empty once moved into a pod netns)
	RepresentorName string // host-side representor netdev name
	BridgeName      string // bridge this PF's uplink/representors are attached to

	// nl is the netlink ops used by Setup and Free.
	// Populated by EswitchSRIOVManager at listDevices / RestoreDevice time.
	// Not serialised — restored devices get the manager's ops re-injected
	// via RestoreDevice.
	nl netlinkOps
}

func (d EswitchPciDevice) GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
	result := make(map[resourceapi.QualifiedName]resourceapi.DeviceAttribute)
	result[types.DriverLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.Driver)}
	result[types.DeviceIDLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.DeviceID)}
	result[types.VendorLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.Vendor)}
	result[types.PFNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.PFName)}
	result[types.PCIBusIDLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.Addr)}
	result[types.KernelIfNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(d.KernelIfName())}

	return result
}

// IfName returns a name for this sr-iov VF. Does not match the kernel
// interface name since it is not guaranteed we have a kernel interface for
// this device. Derived from the PCI address.
func (d EswitchPciDevice) IfName() string {
	return strings.ReplaceAll(strings.ReplaceAll(d.Addr, ":", "-"), ".", "-")
}

func (d EswitchPciDevice) KernelIfName() string {
	return d.KernelIfaceName
}

// Merge carries forward KernelIfaceName if the fresh scan couldn't
// determine one (VF moved into a pod netns and is no longer visible from
// the root namespace). RepresentorName/BridgeName/PFName are always
// resolvable from a fresh host-side scan — the representor stays on the
// host even when the VF itself moves — so those are never carried forward.
func (d *EswitchPciDevice) Merge(old types.Device) {
	if d.KernelIfName() == "" {
		d.KernelIfaceName = old.KernelIfName()
	}
}

// Setup programs VLAN membership for this VF's representor on the bridge.
// A DeviceConfig with Vlan == 0 is a no-op (no VLAN isolation requested).
func (d EswitchPciDevice) Setup(config types.DeviceConfig) error {
	if config.Vlan == 0 {
		return nil
	}

	if d.RepresentorName == "" {
		return fmt.Errorf("failed to set up vf %s (%s): %w", d.IfName(), d.KernelIfName(), errRepresentorNotFound)
	}

	l, err := d.nl.LinkByName(d.RepresentorName)
	if err != nil {
		return fmt.Errorf("failed to retrieve representor link %s: %w", d.RepresentorName, err)
	}

	if bridgeVlanPresent(d.nl, l, uint16(config.Vlan)) {
		// already configured; idempotent no-op.
		return nil
	}

	// Some NICs' switchdev/e-switch VLAN offload (observed on Mellanox/
	// ConnectX representors) intermittently rejects BridgeVlanAdd with
	// EINVAL even though the live bridge VLAN table (as read back via
	// BridgeVlanList) looks perfectly consistent with the request. The
	// call reliably succeeds immediately after the port's bridge
	// enslavement is bounced (NOMASTER then re-MASTER) with no other
	// change to kernel-visible state — this resets some transient
	// driver/firmware-side offload context tied to the port's bridge
	// membership without touching the VLAN table itself. Since this can
	// happen on any BridgeVlanAdd call, bounce unconditionally before
	// every one rather than only after a first failure (see
	// bounceBridgeMembership doc comment).
	if err := bounceBridgeMembership(d.nl, l, d.BridgeName); err != nil {
		return fmt.Errorf("failed to bounce bridge membership for representor %s: %w", d.RepresentorName, err)
	}

	// A bridge port can only have one PVID at a time. A freshly-enslaved
	// port (or one just Free()'d back to its original state) carries
	// defaultBridgeVID as PVID+untagged; that flag must be cleared before
	// the requested VLAN can become the new PVID, or the kernel rejects
	// the add below with EINVAL. Demoting is a no-op if defaultBridgeVID
	// isn't currently the port's PVID (e.g. a previous Setup call for a
	// different VLAN never got Free()'d — shouldn't normally happen, but
	// harmless either way since BridgeVlanAdd here only ever re-asserts
	// defaultBridgeVID as a plain untagged member).
	if uint16(config.Vlan) != defaultBridgeVID && bridgeVlanIsPVID(d.nl, l, defaultBridgeVID) {
		if err := d.nl.BridgeVlanAdd(l, defaultBridgeVID, false, true, false, true); err != nil {
			return fmt.Errorf(
				"failed to demote default vlan %d as pvid on representor %s: %w",
				defaultBridgeVID, d.RepresentorName, err,
			)
		}
	}

	// pvid=true, untagged=true: make config.Vlan this representor port's
	// PVID and strip the 802.1Q tag on egress — VF traffic enters/exits
	// untagged and is tagged with this VLAN only inside the bridge, which
	// is how L2 isolation between VFs on different VLANs is enforced.
	// self=false, master=true: apply the change to the bridge's per-port
	// VLAN table (via the port's bridge master), not to the representor
	// netdevice itself — equivalent to `bridge vlan add ... master` rather
	// than `... self`.
	if err := d.nl.BridgeVlanAdd(l, uint16(config.Vlan), true, true, false, true); err != nil {
		return fmt.Errorf(
			"failed to add vlan id %d to representor %s: %w",
			config.Vlan, d.RepresentorName, err,
		)
	}

	return nil
}

// Free removes VLAN membership for this VF's representor on the bridge.
func (d EswitchPciDevice) Free(config types.DeviceConfig) error {
	if config.Vlan == 0 {
		return nil
	}

	if d.RepresentorName == "" {
		return fmt.Errorf("failed to free vf %s (%s): %w", d.IfName(), d.KernelIfName(), errRepresentorNotFound)
	}

	l, err := d.nl.LinkByName(d.RepresentorName)
	if err != nil {
		return fmt.Errorf("failed to retrieve representor link %s: %w", d.RepresentorName, err)
	}

	if !bridgeVlanPresent(d.nl, l, uint16(config.Vlan)) {
		// already absent; idempotent no-op.
		return nil
	}

	if err := d.nl.BridgeVlanDel(l, uint16(config.Vlan), true, true, false, true); err != nil {
		return fmt.Errorf(
			"failed to remove vlan id %d from representor %s: %w",
			config.Vlan, d.RepresentorName, err,
		)
	}

	// Restore defaultBridgeVID as this port's PVID so it's back in the
	// same pristine state a freshly-enslaved port would be in, ready for
	// a future Setup call (see defaultBridgeVID doc comment). No-op if
	// it's already the PVID.
	if uint16(config.Vlan) != defaultBridgeVID && !bridgeVlanIsPVID(d.nl, l, defaultBridgeVID) {
		// See the matching comment in Setup: bounce bridge membership
		// unconditionally before this BridgeVlanAdd too, since the same
		// intermittent EINVAL can happen here.
		if err := bounceBridgeMembership(d.nl, l, d.BridgeName); err != nil {
			return fmt.Errorf("failed to bounce bridge membership for representor %s: %w", d.RepresentorName, err)
		}

		if err := d.nl.BridgeVlanAdd(l, defaultBridgeVID, true, true, false, true); err != nil {
			return fmt.Errorf(
				"failed to restore default vlan %d as pvid on representor %s: %w",
				defaultBridgeVID, d.RepresentorName, err,
			)
		}
	}

	return nil
}

// Match evaluates a filter to determine if the device matches it.
func (d EswitchPciDevice) Match(filter v2alpha1.CiliumNetworkDriverDeviceFilter) bool {
	if len(filter.DeviceManagers) != 0 {
		if !slices.Contains(filter.DeviceManagers, types.DeviceManagerTypeEswitchSRIOV.String()) {
			return false
		}
	}

	if len(filter.PCIAddrs) != 0 {
		if !slices.Contains(filter.PCIAddrs, d.Addr) {
			return false
		}
	}

	// ifNames matches against the kernel interface name (e.g. "eth0"), not the
	// synthetic PCI-derived IfName() nor the representor name. KernelIfName
	// may be empty for VFs currently assigned to a pod; in that case use
	// pciAddrs.
	if len(filter.IfNames) != 0 {
		if !slices.Contains(filter.IfNames, d.KernelIfName()) {
			return false
		}
	}

	if len(filter.VendorIDs) != 0 {
		if !slices.Contains(filter.VendorIDs, d.Vendor) {
			return false
		}
	}

	if len(filter.DeviceIDs) != 0 {
		if !slices.Contains(filter.DeviceIDs, d.DeviceID) {
			return false
		}
	}

	if len(filter.Drivers) != 0 {
		if !slices.Contains(filter.Drivers, d.Driver) {
			return false
		}
	}

	if len(filter.PFNames) != 0 {
		if !slices.Contains(filter.PFNames, d.PFName) {
			return false
		}
	}

	return true
}

func (d EswitchPciDevice) MarshalBinary() (data []byte, err error) {
	return json.Marshal(d)
}

func (d *EswitchPciDevice) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, &d)
}

type EswitchSRIOVManager struct {
	logger  *slog.Logger
	sysPath string
	config  *v2alpha1.EswitchSRIOVDeviceManagerConfig
	nl      netlinkOps
}

func NewManager(logger *slog.Logger, cfg *v2alpha1.EswitchSRIOVDeviceManagerConfig, opts ...func(*EswitchSRIOVManager)) (*EswitchSRIOVManager, error) {
	mgr := &EswitchSRIOVManager{
		logger:  logger,
		sysPath: cfg.SysPCIDevicesPath,
		config:  cfg,
		nl:      netlinkImpl{},
	}

	for _, opt := range opts {
		opt(mgr)
	}

	if mgr.sysPath == "" {
		mgr.sysPath = defaultSysfsPath
	}

	mgr.logger.Debug(
		"initializing eswitch sr-iov device manager",
		logfields.Path, mgr.sysPath,
	)

	if err := mgr.init(); err != nil {
		mgr.logger.Error("eswitch sr-iov initialization completed with errors", logfields.Error, err)
	}

	return mgr, nil
}

func (mgr *EswitchSRIOVManager) Type() types.DeviceManagerType {
	return types.DeviceManagerTypeEswitchSRIOV
}

// Run publishes the discovered eswitch VF/representor devices once, then
// blocks until ctx is cancelled. The device set is determined by the PF
// configuration at startup, so a single publish is sufficient.
func (mgr *EswitchSRIOVManager) Run(ctx context.Context, publish func([]types.Device)) error {
	devices, err := mgr.listDevices()
	if err != nil {
		return err
	}
	publish(devices)
	<-ctx.Done()
	return nil
}

func (mgr *EswitchSRIOVManager) pciDevicesPath() string {
	return filepath.Join(mgr.sysPath, pciDevicesPath)
}

// init processes each configured PF independently: it switches the PF to
// switchdev eswitch mode (only if no VFs currently exist on it), creates the
// configured VFs, reconciles the PF's referenced bridge (shared bridges are
// reconciled only once), and attaches the PF uplink and each resolvable VF
// representor to that bridge. A failure processing one PF is logged and
// joined into the returned error; other PFs still get processed
// (per-PF partial success — no atomic all-or-nothing behavior).
func (mgr *EswitchSRIOVManager) init() error {
	if len(mgr.config.Ifaces) == 0 {
		return nil
	}

	pciAddrByIfname, err := mgr.pciAddrsByKernelIfname()
	if err != nil {
		return err
	}

	bridgesByName := make(map[string]v2alpha1.EswitchBridgeConfig, len(mgr.config.Bridges))
	for _, b := range mgr.config.Bridges {
		bridgesByName[b.Name] = b
	}

	reconciledBridges := make(map[string]struct{})

	var errs error

	// For each configured PF, run through its setup pipeline in order. Each
	// step can fail independently; a failure is joined into errs and the
	// loop moves on to the next iface (this PF's configuration is skipped
	// for the remainder of this pass — see the partial-success doc comment
	// above init()). The steps are:
	//   1. Resolve the PF's kernel ifname to its PCI bus address.
	//   2. Ensure the PF's eswitch mode is switchdev (switching it from
	//      legacy only if it currently has zero VFs).
	//   3. Create/reconcile this PF's VFs (sriov_numvfs).
	//   4. If no bridge is configured for this PF, stop here — its VFs are
	//      still discovered/advertised, just without VLAN isolation.
	//   5. Otherwise, reconcile (create-or-verify, once per bridge name)
	//      the bridge this PF references.
	//   6. Enslave the PF uplink itself to that bridge (trunk port).
	//   7. Discover and enslave each VF's representor to the same bridge.
	for _, iface := range mgr.config.Ifaces {
		l := mgr.logger.With(logfields.Interface, iface.IfName)

		pfAddr, ok := pciAddrByIfname[KernelIfName(iface.IfName)]
		if !ok {
			errs = errors.Join(errs, fmt.Errorf("pci address not found for ifname %s: %w", iface.IfName, errInterfaceNotFound))
			continue
		}

		devicePath := filepath.Join(mgr.pciDevicesPath(), pfAddr)

		if err := mgr.ensureSwitchdevMode(l, pfAddr, devicePath); err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		if err := mgr.setupPFVFs(l, iface, devicePath); err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		if iface.BridgeName == "" {
			// no bridge configured for this PF: VFs are discovered/advertised
			// normally, but VLAN isolation cannot be enforced (Setup/Free
			// will error if a claim ever requests a VLAN for one of them).
			continue
		}

		bridgeCfg, ok := bridgesByName[iface.BridgeName]
		if !ok {
			errs = errors.Join(errs, fmt.Errorf(
				"pf %s references unknown bridge %q: %w", iface.IfName, iface.BridgeName, errBridgeReconcile,
			))
			continue
		}

		bridgeLink, err := mgr.reconcileBridge(l, bridgeCfg, reconciledBridges)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		uplink, err := mgr.nl.LinkByName(iface.IfName)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to retrieve uplink %s: %w", iface.IfName, err))
			continue
		}

		if err := mgr.attachToBridge(uplink, bridgeLink); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to enslave uplink %s to bridge %s: %w", iface.IfName, bridgeCfg.Name, err))
			continue
		}

		if err := mgr.attachRepresentors(l, iface, pfAddr, devicePath, bridgeLink); err != nil {
			errs = errors.Join(errs, err)
		}
	}

	return errs
}

// ensureSwitchdevMode switches pfAddr's eswitch mode to switchdev if it is
// currently legacy and has no VFs configured. If VFs already exist, the mode
// is left untouched and an error is returned (logged by the caller via
// errors.Join, not treated as fatal to other PFs).
func (mgr *EswitchSRIOVManager) ensureSwitchdevMode(l *slog.Logger, pfAddr, devicePath string) error {
	devices, err := mgr.nl.DevLinkGetDeviceList()
	if err != nil {
		return fmt.Errorf("failed to list devlink devices: %w", err)
	}

	var dev *netlink.DevlinkDevice
	for _, d := range devices {
		if d.BusName == pciBusName && d.DeviceName == pfAddr {
			dev = d
			break
		}
	}

	if dev == nil {
		return fmt.Errorf("pf %s: %w", pfAddr, errDevlinkDeviceNotFound)
	}

	if dev.Attrs.Eswitch.Mode == eswitchModeSwitchdev {
		return nil
	}

	_, numVFs, err := getVFs(devicePath)
	if err != nil {
		return fmt.Errorf("failed reading vf count for pf %s: %w", pfAddr, err)
	}

	if numVFs > 0 {
		return fmt.Errorf("pf %s has %d vfs configured: %w", pfAddr, numVFs, errVFsExistCannotSwitchMode)
	}

	if err := mgr.nl.DevLinkSetEswitchMode(dev, eswitchModeSwitchdev); err != nil {
		return fmt.Errorf("failed to switch pf %s to switchdev mode: %w", pfAddr, err)
	}

	l.Info("switched pf to switchdev eswitch mode", logfields.Device, pfAddr)

	return nil
}

// setupPFVFs configures a single PF with the requested number of VFs by
// writing to `sriov_numvfs` in sysfs. Mirrors sriov.SRIOVManager.setupVFs
// but scoped to a single already-resolved PF.
func (mgr *EswitchSRIOVManager) setupPFVFs(l *slog.Logger, iface v2alpha1.EswitchSRIOVDeviceConfig, devicePath string) error {
	maxVFs, numVFs, err := getVFs(devicePath)
	if err != nil {
		return fmt.Errorf("failed retrieving vfs for interface %s: %w", iface.IfName, err)
	}

	if iface.VFCount > maxVFs {
		return fmt.Errorf(
			"failed to set up sriov vfs on %s. max: %d, want: %d: %w",
			iface.IfName, maxVFs, iface.VFCount, errTooManyVFs,
		)
	}

	if numVFs > 0 {
		l.Info("sriov_numvfs is already set. not changing it")
		if numVFs != iface.VFCount {
			l.Warn(`vf count in configuration for interface is different from current configuration.
					in order to change the vf count, the sriov configuration must be reset on the pf by
					removing all existing VFs. ignoring configuration`,
			)
		}

		return nil
	}

	if err := writeVFs(devicePath, iface.VFCount); err != nil {
		return fmt.Errorf("failed to set sriov_numvfs for %s: %w", iface.IfName, err)
	}

	l.Info("sriov configuration complete", logfields.VFCount, iface.VFCount)

	return nil
}

// attachRepresentors finds and attaches the representor for every VF
// currently present on the PF at pfAddr/devicePath. VFs whose representor
// cannot be resolved are skipped (logged), since parseDevice will also skip
// them at discovery time and they must never be advertised.
func (mgr *EswitchSRIOVManager) attachRepresentors(l *slog.Logger, iface v2alpha1.EswitchSRIOVDeviceConfig, pfAddr, devicePath string, bridgeLink netlink.Link) error {
	entries, err := os.ReadDir(devicePath)
	if err != nil {
		return fmt.Errorf("failed to read pf device dir %s: %w", devicePath, err)
	}

	var errs error

	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "virtfn") {
			continue
		}

		vfID, err := strconv.Atoi(strings.TrimPrefix(name, "virtfn"))
		if err != nil {
			continue
		}

		repName, err := mgr.findRepresentor(pfAddr, vfID)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("pf %s vf %d: %w", iface.IfName, vfID, err))
			continue
		}
		if repName == "" {
			l.Warn(
				"vf has no resolvable representor, its device will not be advertised",
				logfields.Interface, iface.IfName,
				logfields.VFID, vfID,
			)
			continue
		}

		repLink, err := mgr.nl.LinkByName(repName)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to retrieve representor %s: %w", repName, err))
			continue
		}

		if err := mgr.attachToBridge(repLink, bridgeLink); err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed to attach representor to bridge %s: %w", repName, err))
		}
	}

	return errs
}

// findRepresentor returns the host netdev name of the VF representor for
// vfID on the PF identified by pfAddr (its PCI bus address, e.g.
// "0000:17:00.2"), or "" (with a nil error) if none is found.
//
// Resolution is via devlink ports, not sysfs: every PCI function's devlink
// port reports its own PF/VF number directly (Fn.PfNumber/Fn.VfNumber), so a
// VF representor port is identified by matching BusName/DeviceName against
// the PF's own devlink device and PortFlavour == PCI_VF, then comparing
// VfNumber to vfID — no phys_port_name string parsing required.
func (mgr *EswitchSRIOVManager) findRepresentor(pfAddr string, vfID int) (string, error) {
	ports, err := mgr.nl.DevLinkGetAllPortList()
	if err != nil {
		return "", fmt.Errorf("failed to list devlink ports: %w", err)
	}

	for _, p := range ports {
		if p == nil {
			continue
		}
		if p.BusName != pciBusName || p.DeviceName != pfAddr {
			continue
		}
		if p.PortFlavour != nl.DEVLINK_PORT_FLAVOUR_PCI_VF {
			continue
		}
		if p.VfNumber == nil || int(*p.VfNumber) != vfID {
			continue
		}

		return p.NetdeviceName, nil
	}

	return "", nil
}

// vfIndexFromPhysPortName parses the switchdev representor phys_port_name
// convention "pf<N>vf<M>" (e.g. "pf0vf3" -> PF index 0, VF index 3) and
// returns M, the VF index, plus ok=true on a match. Any other form
// (including the plain "p<N>" uplink naming) reports ok=false. Used by
// kernelIfName to exclude VF representor entries when resolving a PF's own
// kernel ifname from its net/ sysfs directory (representor resolution
// itself uses devlink ports — see findRepresentor above).
func vfIndexFromPhysPortName(portName string) (vfIndex int, ok bool) {
	rest, ok := strings.CutPrefix(portName, "pf")
	if !ok {
		return 0, false
	}

	// skip the PF index digits.
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, false
	}
	rest = rest[i:]

	rest, ok = strings.CutPrefix(rest, "vf")
	if !ok || rest == "" {
		return 0, false
	}

	vf, err := strconv.Atoi(rest)
	if err != nil {
		return 0, false
	}

	return vf, true
}

// listDevices scans the system to find sr-iov virtual functions on eswitch-
// managed PFs and resolves each one's representor.
func (mgr *EswitchSRIOVManager) listDevices() ([]types.Device, error) {
	var result []types.Device

	bridgeByIfName := make(map[string]string, len(mgr.config.Ifaces))
	for _, iface := range mgr.config.Ifaces {
		bridgeByIfName[iface.IfName] = iface.BridgeName
	}

	if err := filepath.WalkDir(mgr.pciDevicesPath(), func(root string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			mgr.logger.Error(
				"failed to access directory",
				logfields.Path, root,
				logfields.Error, walkErr.Error(),
			)

			return nil
		}

		addr := d.Name()

		l := mgr.logger.With(
			logfields.Device, addr,
			logfields.FilePath, root,
		)

		if !isNetworkDevice(root) || !isVF(root) {
			return nil
		}

		device, err := mgr.parseDevice(addr, bridgeByIfName)
		if err != nil {
			l.Warn("failed to parse device", logfields.Error, err)
			return nil
		}
		if device == nil {
			// valid VF, but no resolvable representor: intentionally not
			// advertised.
			return nil
		}

		device.nl = mgr.nl
		result = append(result, device)

		return nil
	}); err != nil {
		return nil, err
	}

	return result, nil
}

func (mgr *EswitchSRIOVManager) RestoreDevice(data []byte) (types.Device, error) {
	var dev EswitchPciDevice
	if err := dev.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	dev.nl = mgr.nl
	return &dev, nil
}

type PCIAddr string
type KernelIfName string

// kernelIfName returns the kernel netdev name for the PCI device at
// devicePath, or ok=false if it has none (e.g. no net/ subdir, or the only
// entries present are VF representors — see vfIndexFromPhysPortName).
//
// A PF's device directory holds one net/ entry per eswitch port: its own
// uplink plus one entry per VF representor. Representors are excluded via
// their phys_port_name ("pf<N>vf<M>"), leaving the uplink's own entry. A
// plain PCI device (VF or non-SR-IOV NIC) has at most one net/ entry, which
// is returned as-is.
func kernelIfName(devicePath string) (string, bool) {
	netDir := filepath.Join(devicePath, "net")

	entries, err := os.ReadDir(netDir)
	if err != nil {
		return "", false
	}

	for _, e := range entries {
		name := e.Name()

		portName, err := os.ReadFile(filepath.Join(netDir, name, "phys_port_name"))
		if err == nil {
			if _, ok := vfIndexFromPhysPortName(strings.TrimSpace(string(portName))); ok {
				// VF representor, not the uplink/VF's own netdev.
				continue
			}
		}

		return name, true
	}

	return "", false
}

// isEnslavedTo reports whether the netdev at netDevDir (a
// .../net/<ifname> sysfs directory) is currently enslaved to a master
// device named bridgeName, read directly from the "master" symlink (which
// points at .../virtual/net/<bridge-name> for a bridge master).
func isEnslavedTo(netDevDir, bridgeName string) bool {
	target, err := os.Readlink(filepath.Join(netDevDir, "master"))
	if err != nil {
		return false
	}

	return filepath.Base(target) == bridgeName
}

// pciAddrsByKernelIfname scans every PCI device under mgr.pciDevicesPath()
// and returns a map from kernel interface name to PCI address, for devices
// that have a resolvable non-representor netdev (see kernelIfName). Used
// by init() to resolve each configured PF's kernel ifname to its PCI
// address.
func (mgr *EswitchSRIOVManager) pciAddrsByKernelIfname() (map[KernelIfName]string, error) {
	entries, err := os.ReadDir(mgr.pciDevicesPath())
	if err != nil {
		return nil, err
	}

	result := make(map[KernelIfName]string, len(entries))

	for _, e := range entries {
		addr := e.Name()
		name, ok := kernelIfName(filepath.Join(mgr.pciDevicesPath(), addr))
		if !ok {
			continue
		}

		result[KernelIfName(name)] = addr
	}

	return result, nil
}

// parseDevice constructs an EswitchPciDevice from a PCI device's sysfs
// attributes and resolves its representor. Returns (nil, nil) if the VF is
// valid but has no resolvable representor — such devices are intentionally
// not advertised, distinct from (nil, err) which indicates a parse failure
// worth logging.
func (mgr *EswitchSRIOVManager) parseDevice(addr string, bridgeByIfName map[string]string) (*EswitchPciDevice, error) {
	dev := EswitchPciDevice{
		Addr: addr,
	}

	devicePath := filepath.Join(mgr.pciDevicesPath(), addr)

	if name, ok := kernelIfName(devicePath); ok {
		dev.KernelIfaceName = name
	}

	driver, err := os.Readlink(filepath.Join(devicePath, "driver"))
	if err != nil {
		return nil, err
	}
	dev.Driver = filepath.Base(driver)

	vendor, err := os.ReadFile(filepath.Join(devicePath, "vendor"))
	if err != nil {
		return nil, err
	}
	dev.Vendor = strings.TrimSpace(string(vendor))

	device, err := os.ReadFile(filepath.Join(devicePath, "device"))
	if err != nil {
		return nil, err
	}
	dev.DeviceID = strings.TrimSpace(string(device))

	pfPath, err := os.Readlink(filepath.Join(devicePath, "physfn"))
	if err != nil {
		return nil, errNotAVF
	}

	pfAddr := filepath.Base(pfPath)
	pfDevPath := filepath.Join(mgr.pciDevicesPath(), pfAddr)

	pfName, ok := kernelIfName(pfDevPath)
	if !ok {
		return nil, fmt.Errorf("pf kernel ifname for device %s: %w", pfAddr, errInterfaceNotFound)
	}

	dev.PFName = pfName
	dev.BridgeName = bridgeByIfName[pfName]

	if dev.BridgeName != "" && !isEnslavedTo(filepath.Join(pfDevPath, "net", pfName), dev.BridgeName) {
		// PF is configured to use a bridge but isn't actually enslaved
		// to it: init() failed to reconcile this PF (bad bridge param,
		// missing bridge, etc). Don't advertise its VFs as usable
		// devices until that's fixed and a fresh scan sees it enslaved.
		return nil, nil
	}

	// Resolve the VF index by scanning the PF's virtfn* sysfs symlinks
	// directly.
	entries, err := os.ReadDir(pfDevPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read pf device dir %s: %w", pfDevPath, err)
	}

	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "virtfn") {
			continue
		}

		vfID, err := strconv.Atoi(strings.TrimPrefix(name, "virtfn"))
		if err != nil {
			continue
		}

		v, err := os.Readlink(filepath.Join(pfDevPath, name))
		if err != nil {
			continue
		}

		vfAddr := filepath.Base(v)
		if vfAddr != addr {
			continue
		}

		dev.VFID = vfID

		repName, err := mgr.findRepresentor(pfAddr, dev.VFID)
		if err != nil {
			return nil, err
		}
		if repName == "" {
			// valid VF, but no representor: skip advertising it entirely.
			return nil, nil
		}
		dev.RepresentorName = repName

		return &dev, nil
	}

	return nil, errVFIDNotFound
}

const (
	// https://elixir.bootlin.com/linux/v6.17.6/source/include/linux/pci_ids.h#L32
	// #define PCI_CLASS_NETWORK_ETHERNET	0x0200
	ethernetDeviceClass = 0x0200
)

// isNetworkDevice checks the PCI device class and returns whether it is a network device.
// see `ethernetDeviceClass“ definition for more context.
func isNetworkDevice(pciDevPath string) bool {
	deviceClassFilePath := filepath.Join(pciDevPath, "class")
	f, err := os.ReadFile(deviceClassFilePath)
	if err != nil {
		return false
	}

	v, err := strconv.ParseUint(strings.TrimSpace(string(f)), 0, 32)
	if err != nil {
		return false
	}

	// get just the first 2 bytes, ignore subclass part
	v = v >> 8

	return v == ethernetDeviceClass
}

// getVFs returns the values for sriov_totalvfs and sriov_numvfs for a
// device at path `devicePath`
func getVFs(devicePath string) (maxVFsInt, numVFsInt int, err error) {
	maxVFsStr, err := os.ReadFile(filepath.Join(devicePath, "sriov_totalvfs"))
	if err != nil {
		return 0, 0, fmt.Errorf(
			"could not read sriov_totalvfs file %s: %w",
			devicePath, err,
		)
	}

	maxVFs, err := strconv.ParseUint(strings.TrimSpace(string(maxVFsStr)), 0, 32)
	if err != nil {
		return 0, 0, fmt.Errorf(
			"could not parse int for sriov_totalvfs at file %s: %w",
			devicePath, err,
		)
	}

	numVFsStr, err := os.ReadFile(filepath.Join(devicePath, "sriov_numvfs"))
	if err != nil {
		return 0, 0, fmt.Errorf(
			"could not read sriov_numvfs file %s: %w",
			devicePath, err,
		)
	}

	numVFs, err := strconv.ParseUint(strings.TrimSpace(string(numVFsStr)), 0, 32)
	if err != nil {
		return 0, 0, fmt.Errorf(
			"could not parse int for sriov_numvfs for %s: %w",
			devicePath, err,
		)
	}

	return int(maxVFs), int(numVFs), nil
}

// isVF returns whether the PCI device is an sr-iov vf or not.
// we know if this is a VF if there is a `physfn` link in /sys/bus/pci/devices/<vf_pci_addr> path
func isVF(pciDevPath string) bool {
	_, err := os.Stat(filepath.Join(pciDevPath, "physfn"))
	return err == nil
}

// writeVFs writes vfCount to this device's sriov_numvfs file.
func writeVFs(devicePath string, vfCount int) error {
	return os.WriteFile(filepath.Join(devicePath, "sriov_numvfs"),
		[]byte(strconv.Itoa(vfCount)),
		os.ModeAppend)
}
