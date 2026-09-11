// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// https://elixir.bootlin.com/linux/v6.17.6/source/include/linux/pci_ids.h#L32
	// #define PCI_CLASS_NETWORK_ETHERNET	0x0200
	ethernetDeviceClass = 0x0200
)

// IsNetworkDevice checks the PCI device class and returns whether it is a network device.
// see `ethernetDeviceClass“ definition for more context.
func IsNetworkDevice(pciDevPath string) bool {
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

// IsVF returns whether the PCI device is an sr-iov vf or not.
// we know if this is a VF if there is a `physfn` link in /sys/bus/pci/devices/<vf_pci_addr> path
func IsVF(pciDevPath string) bool {
	_, err := os.Stat(filepath.Join(pciDevPath, "physfn"))
	return err == nil
}

// WriteVFs writes vfCount to this device's sriov_numvfs file.
func WriteVFs(devicePath string, vfCount int) error {
	return os.WriteFile(filepath.Join(devicePath, "sriov_numvfs"),
		[]byte(strconv.Itoa(vfCount)),
		os.ModeAppend)
}

// GetVFs returns the values for sriov_totalvfs and sriov_numvfs for a
// device at path `devicePath`
func GetVFs(devicePath string) (maxVFsInt, numVFsInt int, err error) {
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
