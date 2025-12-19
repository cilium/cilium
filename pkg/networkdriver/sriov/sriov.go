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

var (
	errNotAVF               = errors.New("device is not a vf")
	errTooManyVfs           = errors.New("too many vfs")
	errPfAttributesNotFound = errors.New("pf netlink attributes missing")
)

type MacAddr [6]byte

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
	result[types.DeviceManagerLabel] = resourceapi.DeviceAttribute{StringValue: ptr.To(types.DeviceManagerTypeSRIOV.String())}

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
	logger  *slog.Logger
	sysPath string
	config  *v2alpha1.SRIOVDeviceManagerConfig
}

func (m *SRIOVManager) init() error {
	if m.sysPath == "" {
		m.sysPath = defaultSysPath
	}

	m.logger.Debug(
		"initializing sr-iov device manager",
		logfields.Path, m.sysPath,
	)

	for _, intf := range m.config.Ifaces {
		if intf.VfCount != 0 {
			if err := setupVfs(intf.IfName, intf.VfCount, m.logger); err != nil {
				return err
			}
		}
	}

	return nil
}

func NewManager(logger *slog.Logger, cfg *v2alpha1.SRIOVDeviceManagerConfig) (*SRIOVManager, error) {
	mgr := &SRIOVManager{
		logger:  logger,
		sysPath: cfg.SysPciDevicesPath,
		config:  cfg,
	}

	return mgr, mgr.init()
}

// ListDevices scans the system to find sr-iov virtual functions.
func (mgr *SRIOVManager) ListDevices() ([]types.Device, error) {
	files, err := os.ReadDir(mgr.sysPath)
	if err != nil {
		return nil, err
	}

	var (
		result []types.Device
		errs   []error
	)

	netlinkAttrs, err := getLinkAttributes()
	if err != nil {
		return nil, err
	}

	for _, dirName := range files {
		addr := dirName.Name()

		if !isNetworkDevice(mgr.sysPath, addr) {
			// we are only interested in network devices for now
			mgr.logger.Debug(
				"skipping non network device",
				logfields.Device, addr,
			)

			continue
		}

		if !isVF(mgr.sysPath, addr) {
			// only interested in sriov vfs
			mgr.logger.Debug(
				"skipping non vf device",
				logfields.Device, addr,
			)

			continue
		}

		device, err := mgr.parseDevice(addr, netlinkAttrs)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse device %s: %w", addr, err))
			continue
		}

		if device != nil {
			result = append(result, *device)
		}
	}

	return result, errors.Join(errs...)
}

const (
	defaultSysPath = "/sys/bus/pci/devices"
	defaultNetPath = "/sys/class/net"
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

// getLinkAttributes returns the netlink attributes for PCI based devices. indexed by PCI address
func getLinkAttributes() (map[string]netlink.LinkAttrs, error) {
	links, err := safenetlink.LinkList()
	if err != nil {
		return nil, err
	}

	result := make(map[string]netlink.LinkAttrs)

	for _, l := range links {
		attrs := l.Attrs()
		if attrs.ParentDev != "" {
			result[attrs.ParentDev] = *attrs
		}
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
func (mgr *SRIOVManager) parseDevice(addr string, netlinkAttrs map[string]netlink.LinkAttrs) (*PciDevice, error) {
	dev := PciDevice{
		addr: addr,
	}

	thisLinkAttrs, ok := netlinkAttrs[addr]
	if ok {
		dev.kernelIfName = thisLinkAttrs.Name
	}

	devicePath := path.Join(mgr.sysPath, addr)
	driver, err := os.Readlink(path.Join(devicePath, "driver"))
	if err != nil {
		return nil, err
	}

	// 	/sys/bus/pci/devices/0000:02:00.0# readlink driver
	// ../../../../bus/pci/drivers/mlx5_core
	_, driver = path.Split(driver)
	dev.driver = driver

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
		return nil, fmt.Errorf("%s %w", addr, errNotAVF)
	}

	_, pfAddr := path.Split(pfPath)

	pfAttrs, ok := netlinkAttrs[pfAddr]
	if !ok {
		return &dev, nil
	}

	dev.pfName = pfAttrs.Name
	pfDevPath := path.Join(mgr.sysPath, pfAddr)

	// now we need to find the vf id
	var found bool

	for _, vf := range pfAttrs.Vfs {
		// root@c3-small-x86-01-bernardo:/sys/class/net/enp2s0f0np0/device# readlink virtfn0
		// ../0000:02:00.2
		// root@c3-small-x86-01-bernardo:/sys/class/net/enp2s0f0np0/device# readlink virtfn1
		// ../0000:02:00.3
		v, err := os.Readlink(path.Join(pfDevPath, fmt.Sprintf("virtfn%d", vf.ID)))
		if err != nil {
			continue
		}

		_, vfAddr := path.Split(v)
		if vfAddr == addr {
			dev.vfID = vf.ID
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("failed to find address %s in the pf %s vf list", addr, pfAttrs.Name)
	}

	return &dev, nil
}

// setupVfs configures a PF that has an `ifname` with `vfCount` virtual functions by
// writing to  `sriov_totalvfs` device attribute in sysfs.
func setupVfs(ifname string, vfCount int, logger *slog.Logger) error {
	devicePath := path.Join(defaultNetPath, ifname, "device")
	maxVfsStr, err := os.ReadFile(path.Join(devicePath, "sriov_totalvfs"))
	if err != nil {
		return fmt.Errorf("could not read sriov_totalvfs file for %s: %w", ifname, err)
	}

	maxVfs, err := strconv.ParseInt(strings.ReplaceAll(string(maxVfsStr), "\n", ""), 0, 32)
	if err != nil {
		return fmt.Errorf("could not parse int for sriov_totalvfs for %s: %w", ifname, err)
	}

	if vfCount > int(maxVfs) {
		return fmt.Errorf(
			"failed to set up sriov vfs on %s: %w. max: %d, want: %d",
			ifname, errTooManyVfs, maxVfs, vfCount)
	}

	numVfsStr, err := os.ReadFile(path.Join(devicePath, "sriov_numvfs"))
	if err != nil {
		return fmt.Errorf("could not read sriov_numvfs file for %s: %w", ifname, err)
	}

	numVfs, err := strconv.ParseInt(strings.ReplaceAll(string(numVfsStr), "\n", ""), 0, 32)
	if err != nil {
		return fmt.Errorf("could not parse int for sriov_numvfs for %s: %w", ifname, err)
	}

	// if there is an existing configuration (that is, there are vfs configured)
	// we don't want to change that as it may disrupt existing VFs
	// print out logging messages so the operator can intervene if the change was intentional.
	if numVfs > 0 {
		logger.Info(fmt.Sprintf("sriov_numvfs is already set for %s. not changing it", ifname))
		if numVfs != int64(vfCount) {
			logger.Error(fmt.Sprintf(`vf count in configuration for %s is different from current configuration.
						in order to change the vf count, the sriov configuration must be reset on the pf by
						removing all existing VFs. ignoring configuration`, ifname),
			)
		}

		return nil
	}

	// if we get here, then the PF has no VFs configured. let's set it up
	if err := os.WriteFile(path.Join(devicePath, "sriov_numvfs"),
		fmt.Appendf(nil, "%d", vfCount),
		os.ModeAppend); err != nil {
		return fmt.Errorf("failed to set sriov_numvfs for %s: %w", ifname, err)
	}

	logger.Info(
		"sriov configuration complete",
		logfields.Interface, ifname,
		logfields.VfCount, vfCount,
	)

	return nil
}
