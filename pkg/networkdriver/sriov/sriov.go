// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sriov

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"

	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/utils/ptr"

	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
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
	errTooManyVfs        = errors.New("too many vfs")
	errInterfaceNotFound = errors.New("interface not found")
	errVFIDNotFound      = errors.New("could not find VF ID")
)

type PCIAddr string
type KernelIfName string

type PciDevice struct {
	addr         string
	driver       string
	vendor       string
	deviceID     string
	pfName       string
	vfID         int
	kernelIfName string
}

func (p PciDevice) GetAttrs() map[resourceapi.QualifiedName]resourceapi.DeviceAttribute {
	result := make(map[resourceapi.QualifiedName]resourceapi.DeviceAttribute)
	result[types.DriverLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.driver)}
	result[types.DeviceIDLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.deviceID)}
	result[types.VendorLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.vendor)}
	result[types.PFNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.pfName)}
	result[types.PCIAddrLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.addr)}
	result[types.IfNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.IfName())}
	result[types.KernelIfNameLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.kernelIfName)}

	return result
}

// IfName returns a name for this sr-iov VF. Does not match kernel interface name since it is not
// guaranteed that we have a kernel interface for this device.
// constructed with <pfName>vf<vfID>
func (d PciDevice) IfName() string {
	return fmt.Sprintf("%svf%d", d.pfName, d.vfID)
}

func (d PciDevice) KernelIfName() string {
	return d.kernelIfName
}

// Setup prepares a sr-iov VF device for use.
func (d PciDevice) Setup(config types.DeviceConfig) error {
	if d.pfName == "" {
		return fmt.Errorf("device with ifname %s %w", d.IfName(), errNotAVF)
	}

	l, err := safenetlink.LinkByName(d.pfName)
	if err != nil {
		return err
	}

	if config.Vlan != 0 {
		return netlink.LinkSetVfVlan(l, d.vfID, int(config.Vlan))
	}

	return nil
}

// Free resets a sr-iov VF device.
func (d PciDevice) Free(config types.DeviceConfig) error {
	if d.pfName == "" {
		return fmt.Errorf("device with ifname %s %w", d.IfName(), errNotAVF)
	}

	l, err := safenetlink.LinkByName(d.pfName)
	if err != nil {
		return err
	}

	if config.Vlan != 0 {
		return netlink.LinkSetVfVlan(l, d.vfID, 0)
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
		if !slices.Contains(filter.PCIAddrs, d.addr) {
			return false
		}
	}

	if len(filter.IfNames) != 0 {
		if !slices.Contains(filter.IfNames, d.IfName()) {
			return false
		}
	}

	if len(filter.VendorIDs) != 0 {
		if !slices.Contains(filter.VendorIDs, d.vendor) {
			return false
		}
	}

	if len(filter.DeviceIDs) != 0 {
		if !slices.Contains(filter.DeviceIDs, d.deviceID) {
			return false
		}
	}

	if len(filter.Drivers) != 0 {
		if !slices.Contains(filter.Drivers, d.driver) {
			return false
		}
	}

	if len(filter.PfNames) != 0 {
		if !slices.Contains(filter.PfNames, d.pfName) {
			return false
		}
	}

	return true
}

type SRIOVManager struct {
	logger            *slog.Logger
	sysPath           string
	config            *v2alpha1.SRIOVDeviceManagerConfig
	netlinkLinkLister func() ([]netlink.Link, error)
}

func withNetlinkLister(f func() ([]netlink.Link, error)) func(*SRIOVManager) {
	return func(s *SRIOVManager) {
		s.netlinkLinkLister = f
	}
}

func (m *SRIOVManager) init() error {
	if m.sysPath == "" {
		m.sysPath = defaultSysfsPath
	}

	m.logger.Debug(
		"initializing sr-iov device manager",
		logfields.Path, m.sysPath,
	)

	if err := m.setupVfs(m.config.Ifaces); err != nil {
		return err
	}

	return nil
}

func NewManager(logger *slog.Logger, cfg *v2alpha1.SRIOVDeviceManagerConfig, opts ...func(*SRIOVManager)) (*SRIOVManager, error) {
	mgr := &SRIOVManager{
		logger:            logger,
		sysPath:           cfg.SysPciDevicesPath,
		config:            cfg,
		netlinkLinkLister: safenetlink.LinkList,
	}

	for _, opt := range opts {
		opt(mgr)
	}

	return mgr, mgr.init()
}

func (mgr *SRIOVManager) pciDevicesPath() string {
	return path.Join(mgr.sysPath, pciDevicesPath)
}

// ListDevices scans the system to find sr-iov virtual functions.
func (mgr *SRIOVManager) ListDevices() ([]types.Device, error) {
	files, err := os.ReadDir(mgr.pciDevicesPath())
	if err != nil {
		return nil, err
	}

	var (
		result []types.Device
	)

	netlinkAttrs, err := mgr.linkAttrsByPCIAddr()
	if err != nil {
		return nil, err
	}

	for _, dirName := range files {
		addr := dirName.Name()

		l := mgr.logger.With(logfields.Device, addr)

		if !isNetworkDevice(mgr.pciDevicesPath(), addr) {
			// we are only interested in network devices for now
			l.Debug("skipping non network device")
			continue
		}

		if !isVF(mgr.pciDevicesPath(), addr) {
			// only interested in sriov vfs
			l.Debug("skipping non vf device")
			continue
		}

		// errors for device parsing at not cause for returning.
		// if parsing fails, we want to still return all valid
		// devices
		device, err := mgr.parseDevice(addr, netlinkAttrs)
		if err != nil {
			l.Error("failed to parse device", logfields.Error, err)
			continue
		}

		if device != nil {
			result = append(result, *device)
		}
	}

	return result, nil
}

const (
	// https://elixir.bootlin.com/linux/v6.17.6/source/include/linux/pci_ids.h#L32
	// #define PCI_CLASS_NETWORK_ETHERNET	0x0200
	ethernetDeviceClass = 0x0200
)

// isNetworkDevice checks the PCI device class and returns whether it is a network device.
// https://elixir.bootlin.com/linux/v6.17.6/source/include/linux/pci_ids.h#L32
// #define PCI_CLASS_NETWORK_ETHERNET	0x0200
func isNetworkDevice(sysPath, pciAddr string) bool {
	deviceClassPath := path.Join(sysPath, pciAddr, "class")
	f, err := os.ReadFile(deviceClassPath)
	if err != nil {
		return false
	}

	v, err := strconv.ParseInt(strings.ReplaceAll(string(f), "\n", ""), 0, 32)
	if err != nil {
		return false
	}

	// get just the first 2 bytes, ignore subclass part
	v = v >> 8

	return v == ethernetDeviceClass
}

// linkAttrsByPCIAddr returns the netlink attributes for PCI based devices. indexed by PCI address
func (mgr *SRIOVManager) linkAttrsByPCIAddr() (map[PCIAddr]netlink.LinkAttrs, error) {
	links, err := mgr.netlinkLinkLister()
	if err != nil {
		return nil, err
	}

	result := make(map[PCIAddr]netlink.LinkAttrs)

	for _, l := range links {
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
	links, err := mgr.netlinkLinkLister()
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
func isVF(sysPath, pciAddr string) bool {
	_, err := os.Stat(path.Join(sysPath, pciAddr, "physfn"))
	return err == nil
}

// parseDevice constructs a PciDevice from a PCI device's sysfs attributes.
// returns an error if we are unable to resolve the vf attributes. the only exception
// is the kernel ifname, which may or may not be present depending on the driver in use.
func (mgr *SRIOVManager) parseDevice(addr string, netlinkAttrs map[PCIAddr]netlink.LinkAttrs) (*PciDevice, error) {
	dev := PciDevice{
		addr: addr,
	}

	thisLinkAttrs, ok := netlinkAttrs[PCIAddr(addr)]
	if ok {
		dev.kernelIfName = thisLinkAttrs.Name
	}

	devicePath := path.Join(mgr.pciDevicesPath(), addr)
	driver, err := os.Readlink(path.Join(devicePath, "driver"))
	if err != nil {
		return nil, err
	}

	// 	/sys/bus/pci/devices/0000:02:00.0# readlink driver
	// ../../../../bus/pci/drivers/mlx5_core
	dev.driver = path.Base(driver)

	vendor, err := os.ReadFile(path.Join(devicePath, "vendor"))
	if err != nil {
		return nil, err
	}

	dev.vendor = strings.ReplaceAll(string(vendor), "\n", "")

	device, err := os.ReadFile(path.Join(devicePath, "device"))
	if err != nil {
		return nil, err
	}

	dev.deviceID = strings.ReplaceAll(string(device), "\n", "")

	pfPath, err := os.Readlink(path.Join(devicePath, "physfn"))
	if err != nil {
		// this is not a vf
		return nil, errNotAVF
	}

	pfAddr := path.Base(pfPath)

	pfAttrs, ok := netlinkAttrs[PCIAddr(pfAddr)]
	if !ok {
		return nil, fmt.Errorf("pf kernel ifname for device %s: %w", pfAddr, errInterfaceNotFound)
	}

	dev.pfName = pfAttrs.Name
	pfDevPath := path.Join(mgr.pciDevicesPath(), pfAddr)

	// now we need to find the vf id
	var found bool

	// to resolve the VF id, we iterate over all VFs under the PF attributes
	// and map the ids to the `virtfn$x` path under the pf device.
	// if the path linked matches the path of our vf address, then we found the id.
	for _, vf := range pfAttrs.Vfs {
		// root@c3-small-x86-01-bernardo:/sys/class/net/enp2s0f0np0/device# readlink virtfn0
		// ../0000:02:00.2
		// root@c3-small-x86-01-bernardo:/sys/class/net/enp2s0f0np0/device# readlink virtfn1
		// ../0000:02:00.3
		v, err := os.Readlink(path.Join(pfDevPath, fmt.Sprintf("virtfn%d", vf.ID)))
		if err != nil {
			continue
		}

		vfAddr := path.Base(v)
		if vfAddr == addr {
			dev.vfID = vf.ID
			found = true
			break
		}
	}

	if !found {
		return nil, errVFIDNotFound
	}

	return &dev, nil
}

// setupVfs configures a PF that has an `ifname` with `vfCount` virtual functions by
// writing to  `sriov_totalvfs` device attribute in sysfs.
func (mgr *SRIOVManager) setupVfs(ifaces []v2alpha1.SRIOVDeviceConfig) error {
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

		devicePath := path.Join(mgr.pciDevicesPath(), ifaceAddr.ParentDev)

		maxVfs, numVfs, err := getVfs(devicePath)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("failed retrieving vfs for interface %s: %w", iface.IfName, err))
			continue
		}

		if iface.VfCount > int(maxVfs) {
			errs = errors.Join(errs, fmt.Errorf(
				"failed to set up sriov vfs on %s. max: %d, want: %d: %w",
				iface.IfName, maxVfs, iface.VfCount, errTooManyVfs,
			))

			continue
		}

		// if there is an existing configuration (that is, there are vfs configured)
		// we don't want to change that as it may disrupt existing VFs
		// print out logging messages so the operator can intervene if the change was intentional.
		if numVfs > 0 {
			mgr.logger.Info(fmt.Sprintf("sriov_numvfs is already set for %s. not changing it", iface.IfName))
			if numVfs != iface.VfCount {
				mgr.logger.Error(fmt.Sprintf(`vf count in configuration for %s is different from current configuration.
						in order to change the vf count, the sriov configuration must be reset on the pf by
						removing all existing VFs. ignoring configuration`, iface.IfName),
				)
			}

			continue
		}

		// if we get here, then the PF has no VFs configured. let's set it up
		if err := writeVfs(devicePath, iface.VfCount); err != nil {
			errs = errors.Join(errs, fmt.Errorf(
				"failed to set sriov_numvfs for %s: %w",
				iface.IfName, err,
			))

			continue
		}

		mgr.logger.Info(
			"sriov configuration complete",
			logfields.Interface, iface.IfName,
			logfields.VfCount, iface.VfCount,
		)
	}

	return errs
}

// writeVfs writes vfCount to this device's sriov_numvfs file.
func writeVfs(devicePath string, vfCount int) error {
	return os.WriteFile(path.Join(devicePath, "sriov_numvfs"),
		[]byte(strconv.Itoa(vfCount)),
		os.ModeAppend)
}

// getVfs returns the values for sriov_totalvfs and sriov_numvfs for a
// device at path `devicePath`
func getVfs(devicePath string) (maxVfsInt, numVfsInt int, err error) {
	maxVfsStr, err := os.ReadFile(path.Join(devicePath, "sriov_totalvfs"))
	if err != nil {
		return 0, 0, fmt.Errorf(
			"could not read sriov_totalvfs file %s: %w",
			devicePath, err,
		)
	}

	maxVfs, err := strconv.ParseInt(strings.ReplaceAll(string(maxVfsStr), "\n", ""), 0, 32)
	if err != nil {
		return 0, 0, fmt.Errorf(
			"could not parse int for sriov_totalvfs at file %s: %w",
			devicePath, err,
		)
	}

	numVfsStr, err := os.ReadFile(path.Join(devicePath, "sriov_numvfs"))
	if err != nil {
		return 0, 0, fmt.Errorf(
			"could not read sriov_numvfs file %s: %w",
			devicePath, err,
		)
	}

	numVfs, err := strconv.ParseInt(strings.ReplaceAll(string(numVfsStr), "\n", ""), 0, 32)
	if err != nil {
		return 0, 0, fmt.Errorf(
			"could not parse int for sriov_numvfs for %s: %w",
			devicePath, err,
		)
	}

	return int(maxVfs), int(numVfs), nil

}
