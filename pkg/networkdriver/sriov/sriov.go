// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sriov

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
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

const (
	defaultSysfsPath = "/host/sys"
	pciDevicesPath   = "bus/pci/devices"
)

var (
	errNotAVF            = errors.New("device is not a vf")
	errTooManyVFs        = errors.New("too many vfs")
	errInterfaceNotFound = errors.New("interface not found")
	errVFIDNotFound      = errors.New("could not find VF ID")
)

type PCIAddr string
type KernelIfName string

// netlinkOps abstracts the netlink calls used by SRIOVManager and PciDevice.
// The real implementation delegates to netlink; tests inject a fake.
type netlinkOps interface {
	// LinkList returns all netlink links on the system.
	LinkList() ([]netlink.Link, error)
	// LinkByName returns the link with the given interface name.
	LinkByName(name string) (netlink.Link, error)
	// LinkSetVfVlan sets the VLAN for a VF on a PF link.
	LinkSetVfVlan(link netlink.Link, vf, vlan int) error
}

// netlinkImpl delegates to the production netlink implementations.
type netlinkImpl struct{}

func (netlinkImpl) LinkList() ([]netlink.Link, error) {
	return netlink.LinkList()
}

func (netlinkImpl) LinkByName(name string) (netlink.Link, error) {
	return netlink.LinkByName(name)
}

func (netlinkImpl) LinkSetVfVlan(link netlink.Link, vf, vlan int) error {
	return netlink.LinkSetVfVlan(link, vf, vlan)
}

type PciDevice struct {
	Addr            string
	Driver          string
	Vendor          string
	DeviceID        string
	PFName          string
	VFID            int
	KernelIfaceName string

	// nl is the netlink ops used by Setup and Free.
	// Populated by SRIOVManager at listDevices / RestoreDevice time.
	// Not serialised — restored devices get the manager's ops re-injected
	// via RestoreDevice.
	nl netlinkOps
}

func (p PciDevice) GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
	result := make(map[resourceapi.QualifiedName]resourceapi.DeviceAttribute)
	result[types.DriverLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.Driver)}
	result[types.DeviceIDLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.DeviceID)}
	result[types.VendorLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.Vendor)}
	result[types.PFNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.PFName)}
	result[types.PCIBusIDLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.Addr)}
	result[types.KernelIfNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.KernelIfName())}

	return result
}

// IfName returns a name for this sr-iov VF. Does not match kernel interface name since it is not
// guaranteed that we have a kernel interface for this device.
// derived from the PCI address.
func (d PciDevice) IfName() string {
	return strings.ReplaceAll(strings.ReplaceAll(d.Addr, ":", "-"), ".", "-")
}

func (d PciDevice) KernelIfName() string {
	return d.KernelIfaceName
}

func (d *PciDevice) Merge(old types.Device) {
	// persist the kernel ifname.
	// if a device is assigned to a pod,
	// the root namespace wont be able to see it.
	// keep the previous ifname if available.
	if d.KernelIfName() == "" {
		d.KernelIfaceName = old.KernelIfName()
	}
}

// Setup prepares a sr-iov VF device for use.
func (d PciDevice) Setup(config types.DeviceConfig) error {
	if d.PFName == "" {
		return fmt.Errorf(
			"failed to set up VF: PF name is empty, device with name %s (%s) %w",
			d.IfName(), d.KernelIfName(), errNotAVF,
		)
	}

	l, err := d.nl.LinkByName(d.PFName)
	if err != nil {
		return err
	}

	if config.Vlan != 0 {
		if err := d.nl.LinkSetVfVlan(l, d.VFID, int(config.Vlan)); err != nil {
			return fmt.Errorf(
				"failed to set vlan id %d for vf %d on link %s: %w",
				config.Vlan, d.VFID, l.Attrs().Name, err,
			)
		}
	}

	return nil
}

// Free resets a sr-iov VF device.
func (d PciDevice) Free(config types.DeviceConfig) error {
	if d.PFName == "" {
		return fmt.Errorf(
			"failed to free VF: PF name is empty, device with name %s (%s) %w",
			d.IfName(), d.KernelIfName(), errNotAVF,
		)
	}

	l, err := d.nl.LinkByName(d.PFName)
	if err != nil {
		return fmt.Errorf("failed to retrieve PF link with name %s: %w", d.PFName, err)
	}

	if config.Vlan != 0 {
		if err := d.nl.LinkSetVfVlan(l, d.VFID, 0); err != nil {
			return fmt.Errorf(
				"failed to unset vlan id for vf %d on link %s: %w",
				d.VFID, l.Attrs().Name, err,
			)
		}
	}

	return nil
}

// Match evaluates a filter to determine if the device matches it.
func (d PciDevice) Match(filter v2alpha1.CiliumNetworkDriverDeviceFilter) bool {
	if len(filter.DeviceManagers) != 0 {
		if !slices.Contains(filter.DeviceManagers, types.DeviceManagerTypeSRIOV.String()) {
			return false
		}
	}

	if len(filter.PCIAddrs) != 0 {
		if !slices.Contains(filter.PCIAddrs, d.Addr) {
			return false
		}
	}

	// ifNames matches against the kernel interface name (e.g. "eth0"), not the
	// synthetic PCI-derived IfName(). KernelIfName may be empty for devices
	// bound to userspace drivers (e.g. vfio-pci); in that case use pciAddrs.
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

func (d PciDevice) MarshalBinary() (data []byte, err error) {
	return json.Marshal(d)
}

func (d *PciDevice) UnmarshalBinary(data []byte) error {
	return json.Unmarshal(data, &d)
}

type SRIOVManager struct {
	logger  *slog.Logger
	sysPath string
	config  *v2alpha1.SRIOVDeviceManagerConfig
	nl      netlinkOps
}

func NewManager(logger *slog.Logger, cfg *v2alpha1.SRIOVDeviceManagerConfig, opts ...func(*SRIOVManager)) (*SRIOVManager, error) {
	mgr := &SRIOVManager{
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
		"initializing sr-iov device manager",
		logfields.Path, mgr.sysPath,
	)

	if err := mgr.setupVFs(mgr.config.Ifaces); err != nil {
		return nil, err
	}

	return mgr, nil
}

func (mgr *SRIOVManager) Type() types.DeviceManagerType {
	return types.DeviceManagerTypeSRIOV
}

// Run publishes the discovered SR-IOV VF devices once, then blocks until ctx
// is cancelled. SR-IOV devices are static — determined by the PF configuration
// at startup — so a single publish is sufficient.
func (mgr *SRIOVManager) Run(ctx context.Context, publish func([]types.Device)) error {
	devices, err := mgr.listDevices()
	if err != nil {
		return err
	}
	publish(devices)
	<-ctx.Done()
	return nil
}

func (mgr *SRIOVManager) pciDevicesPath() string {
	return filepath.Join(mgr.sysPath, pciDevicesPath)
}

// listDevices scans the system to find sr-iov virtual functions.
func (mgr *SRIOVManager) listDevices() ([]types.Device, error) {
	var (
		result []types.Device
	)

	netlinkAttrs, err := mgr.linkAttrsByPCIAddr()
	if err != nil {
		return nil, err
	}

	if err := filepath.WalkDir(mgr.pciDevicesPath(), func(root string, d fs.DirEntry, _ error) error {
		if err != nil {
			mgr.logger.Error(
				"failed to access directory",
				logfields.Path, root,
				logfields.Error, err.Error(),
			)

			return nil
		}

		addr := d.Name()

		l := mgr.logger.With(
			logfields.Device, addr,
			logfields.FilePath, root,
		)

		if !isNetworkDevice(root) || !isVF(root) {
			// we are only interested in network devices for now
			// that are sr-iov virtual functions
			return nil
		}

		// errors for device parsing are not cause for returning.
		// if parsing fails, we want to still return all valid
		// devices
		device, err := mgr.parseDevice(addr, netlinkAttrs)
		if err != nil {
			l.Warn("failed to parse device", logfields.Error, err)
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

func (mgr *SRIOVManager) RestoreDevice(data []byte) (types.Device, error) {
	var dev PciDevice
	if err := dev.UnmarshalBinary(data); err != nil {
		return nil, err
	}
	dev.nl = mgr.nl
	return &dev, nil
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

// linkAttrsByPCIAddr returns the netlink attributes for PCI based devices. indexed by PCI address
func (mgr *SRIOVManager) linkAttrsByPCIAddr() (map[PCIAddr]netlink.LinkAttrs, error) {
	links, err := mgr.nl.LinkList()
	if err != nil {
		return nil, err
	}

	result := make(map[PCIAddr]netlink.LinkAttrs, len(links))

	for _, l := range links {
		// if it does not have a `ParentDev` attribute, it is not a PCI device
		// PCI devices have this field filled in with their PCI address
		// ex: `parentbus pci parentdev 0000:b1:00.1`
		if l.Attrs().ParentDev == "" {
			continue
		}

		result[PCIAddr(l.Attrs().ParentDev)] = *l.Attrs()
	}

	return result, nil
}

// linkAttrsByKernelIfname returns the mapping netlink attributes to kernel ifnames.
// indexed by interface name.
func (mgr *SRIOVManager) linkAttrsByKernelIfname() (map[KernelIfName]netlink.LinkAttrs, error) {
	links, err := mgr.nl.LinkList()
	if err != nil {
		return nil, err
	}

	result := make(map[KernelIfName]netlink.LinkAttrs)

	for _, l := range links {
		if l.Attrs().ParentDev == "" {
			continue
		}

		result[KernelIfName(l.Attrs().Name)] = *l.Attrs()
	}

	return result, nil
}

// isVF returns whether the PCI device is an sr-iov vf or not.
// we know if this is a VF if there is a `physfn` link in /sys/bus/pci/devices/<vf_pci_addr> path
func isVF(pciDevPath string) bool {
	_, err := os.Stat(filepath.Join(pciDevPath, "physfn"))
	return err == nil
}

// parseDevice constructs a PciDevice from a PCI device's sysfs attributes.
// returns an error if we are unable to resolve the vf attributes. the only exception
// is the kernel ifname, which may or may not be present depending on the driver in use.
func (mgr *SRIOVManager) parseDevice(addr string, netlinkAttrs map[PCIAddr]netlink.LinkAttrs) (*PciDevice, error) {
	dev := PciDevice{
		Addr: addr,
	}

	thisLinkAttrs, ok := netlinkAttrs[PCIAddr(addr)]
	if ok {
		dev.KernelIfaceName = thisLinkAttrs.Name
	}

	devicePath := filepath.Join(mgr.pciDevicesPath(), addr)
	driver, err := os.Readlink(filepath.Join(devicePath, "driver"))
	if err != nil {
		return nil, err
	}

	// 	/sys/bus/pci/devices/0000:02:00.0# readlink driver
	// ../../../../bus/pci/drivers/mlx5_core
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
		// this is not a vf
		return nil, errNotAVF
	}

	pfAddr := filepath.Base(pfPath)

	pfAttrs, ok := netlinkAttrs[PCIAddr(pfAddr)]
	if !ok {
		return nil, fmt.Errorf("pf kernel ifname for device %s: %w", pfAddr, errInterfaceNotFound)
	}

	dev.PFName = pfAttrs.Name
	pfDevPath := filepath.Join(mgr.pciDevicesPath(), pfAddr)

	// to resolve the VF id, we iterate over all VFs under the PF attributes
	// and map the ids to the `virtfn$x` path under the pf device.
	// if the path linked matches the path of our vf address, then we found the id.
	for _, vf := range pfAttrs.Vfs {
		// root@c3-small-x86-01-bernardo:/sys/class/net/enp2s0f0np0/device# readlink virtfn0
		// ../0000:02:00.2
		// root@c3-small-x86-01-bernardo:/sys/class/net/enp2s0f0np0/device# readlink virtfn1
		// ../0000:02:00.3
		v, err := os.Readlink(filepath.Join(pfDevPath, fmt.Sprintf("virtfn%d", vf.ID)))
		if err != nil {
			continue
		}

		vfAddr := filepath.Base(v)
		if vfAddr == addr {
			dev.VFID = vf.ID
			return &dev, nil
		}
	}

	return nil, errVFIDNotFound
}

// setupVFs configures a PF that has an `ifname` with `vfCount` virtual functions by
// writing to  `sriov_totalvfs` device attribute in sysfs.
func (mgr *SRIOVManager) setupVFs(ifaces []v2alpha1.SRIOVDeviceConfig) error {
	if len(ifaces) == 0 {
		// nothing to do. early exit.
		return nil
	}

	pciAddrByIfname, err := mgr.linkAttrsByKernelIfname()
	if err != nil {
		return err
	}

	var errs error

	for _, iface := range ifaces {
		ifaceAddr, ok := pciAddrByIfname[KernelIfName(iface.IfName)]
		if !ok {
			errs = errors.Join(errs, fmt.Errorf("pci address not found for ifname %s: %w", iface.IfName, errInterfaceNotFound))
			continue
		}

		devicePath := filepath.Join(mgr.pciDevicesPath(), ifaceAddr.ParentDev)

		maxVFs, numVFs, err := getVFs(devicePath)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed retrieving vfs for interface %s: %w", iface.IfName, err))
			continue
		}

		if iface.VFCount > int(maxVFs) {
			errs = errors.Join(errs, fmt.Errorf(
				"failed to set up sriov vfs on %s. max: %d, want: %d: %w",
				iface.IfName, maxVFs, iface.VFCount, errTooManyVFs,
			))

			continue
		}

		// if there is an existing configuration (that is, there are vfs configured)
		// we don't want to change that as it may disrupt existing VFs
		// print out logging messages so the operator can intervene if the change was intentional.
		if numVFs > 0 {
			mgr.logger.Info(fmt.Sprintf("sriov_numvfs is already set for %s. not changing it", iface.IfName))
			if numVFs != iface.VFCount {
				mgr.logger.Warn(`vf count in configuration for interface is different from current configuration.
						in order to change the vf count, the sriov configuration must be reset on the pf by
						removing all existing VFs. ignoring configuration`,
					logfields.Interface, iface.IfName,
				)
			}

			continue
		}

		// if we get here, then the PF has no VFs configured. let's set it up
		if err := writeVFs(devicePath, iface.VFCount); err != nil {
			errs = errors.Join(errs, fmt.Errorf(
				"failed to set sriov_numvfs for %s: %w",
				iface.IfName, err,
			))

			continue
		}

		mgr.logger.Info(
			"sriov configuration complete",
			logfields.Interface, iface.IfName,
			logfields.VFCount, iface.VFCount,
		)
	}

	return errs
}

// writeVFs writes vfCount to this device's sriov_numvfs file.
func writeVFs(devicePath string, vfCount int) error {
	return os.WriteFile(filepath.Join(devicePath, "sriov_numvfs"),
		[]byte(strconv.Itoa(vfCount)),
		os.ModeAppend)
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
