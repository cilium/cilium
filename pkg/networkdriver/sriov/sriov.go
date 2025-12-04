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
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/networkdriver/types"
)

var (
	errNotAVF     = errors.New("device is not a vf")
	errTooManyVfs = errors.New("too many vfs")
)

type SRIOVIntf struct {
	Ifname  string
	VFCount int
}

type SRIOVConfig struct {
	Enabled bool
	Ifaces  []SRIOVIntf
}

func (s SRIOVConfig) IsEnabled() bool {
	return s.Enabled
}

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
	result["driver"] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.driver)}
	result["deviceID"] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.deviceID)}
	result["vendor"] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.vendor)}
	result["pfName"] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.pfName)}
	result["ifName"] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.IfName())}
	result["kernelIfName"] = resourceapi.DeviceAttribute{StringValue: ptr.To(p.kernelIfName)}

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
func (d PciDevice) Match(filter types.DeviceFilter) bool {
	if len(filter.DriverTypes) != 0 {
		if !slices.Contains(filter.DriverTypes, types.DeviceManagerTypeSRIOV) {
			return false
		}
	}

	if len(filter.PciAddrs) != 0 {
		if !slices.Contains(filter.PciAddrs, d.addr) {
			return false
		}
	}

	if len(filter.IfNames) != 0 {
		if !slices.Contains(filter.PciAddrs, d.IfName()) {
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
	config  SRIOVConfig
}

func (m *SRIOVManager) init() error {
	for _, intf := range m.config.Ifaces {
		if intf.VFCount != 0 {
			if err := setupVfs(intf.Ifname, intf.VFCount, m.logger); err != nil {
				return err
			}
		}
	}

	return nil
}

func NewManager(logger *slog.Logger, cfg SRIOVConfig) (*SRIOVManager, error) {
	mgr := &SRIOVManager{
		logger:  logger,
		sysPath: defaultSysPath,
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

	for _, dirName := range files {
		addr := dirName.Name()

		if !isNetworkDevice(addr) {
			// we are only interested in network devices for now
			continue
		}

		device, err := mgr.parseDevice(addr)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to parse device %s: %w", addr, err))
			continue
		}

		result = append(result, *device)
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
func isNetworkDevice(pciAddr string) bool {
	deviceClassPath := path.Join(defaultSysPath, pciAddr, "class")
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

// parseDevice constructs a PciDevice from a PCI device's sysfs attributes.
func (mgr *SRIOVManager) parseDevice(addr string) (*PciDevice, error) {
	dev := PciDevice{
		addr: addr,
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

	kernelIfNames, err := os.ReadDir(path.Join(devicePath, "net"))
	if err != nil {
		return nil, err
	}
	if len(kernelIfNames) > 0 {
		dev.kernelIfName = kernelIfNames[0].Name()
	}

	device, err := os.ReadFile(path.Join(devicePath, "device"))
	if err != nil {
		return nil, err
	}
	dev.deviceID = strings.ReplaceAll(string(device), "\n", "")

	pfNames, err := os.ReadDir(path.Join(devicePath, "physfn", "net"))
	if err != nil {
		return nil, err
	}
	if len(pfNames) > 0 {
		dev.pfName = pfNames[0].Name()
	}

	pfDevPath := path.Join(defaultNetPath, dev.pfName, "device")
	vfCount, err := os.ReadFile(path.Join(pfDevPath, "sriov_numvfs"))
	if err != nil {
		return nil, err
	}
	vfCnt, err := strconv.Atoi(strings.ReplaceAll(string(vfCount), "\n", ""))
	if err != nil {
		return nil, err
	}

	// root@c3-small-x86-01-bernardo:/sys/class/net/enp2s0f0np0/device# readlink virtfn0
	// ../0000:02:00.2
	// root@c3-small-x86-01-bernardo:/sys/class/net/enp2s0f0np0/device# readlink virtfn1
	// ../0000:02:00.3
	var found bool
	for i := range vfCnt {
		vf, err := os.Readlink(path.Join(pfDevPath, fmt.Sprintf("virtfn%d", i)))
		if err != nil {
			continue
		}
		_, vfAddr := path.Split(vf)
		if vfAddr == addr {
			dev.vfID = i
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("failed to find address %s", addr)
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
