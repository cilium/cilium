// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

var SriovCommand = &cobra.Command{
	Use:   "sriov",
	Short: "Cilium SR-IOV commands",
	Long:  `CLI to perform SR-IOV related tasks`,
}

var SriovInfoCommand = &cobra.Command{
	Use:   "info",
	Short: "Cilium SR-IOV commands",
	Long:  `CLI to display SR-IOV related information`,
	Run: func(cmd *cobra.Command, args []string) {
		basePath := "/sys/bus/pci/devices"

		devices, err := os.ReadDir(basePath)
		if err != nil {
			Fatalf("failed to list devices: %s", err.Error())
		}

		var pfs []string

		for _, f := range devices {
			devicePath := path.Join(basePath, f.Name())
			_, err = os.Stat(path.Join(devicePath, "sriov_totalvfs"))
			if err != nil {
				continue
			}
			pfs = append(pfs, f.Name())
		}

		if len(pfs) == 0 {
			fmt.Println("found no sr-iov PFs")
			return
		}

		for i, p := range pfs {
			dev, err := getSriovDevice(basePath, p)
			if err != nil {
				fmt.Fprintf(os.Stdout, "failed to collect sriov information for %s: %s", p, err.Error())
				continue
			}

			fmt.Fprintf(os.Stdout, "%d: ", i)

			printPfInfo(os.Stdout, basePath, *dev)
		}
	},
}

func init() {
	SriovCommand.AddCommand(SriovInfoCommand)
	RootCmd.AddCommand(SriovCommand)
}

type pciDevice struct {
	addr, driver, vendor, device string
	kernelIfnames                []string
}

type sriovDevice struct {
	pciDevice
	numVfs, totalVfs, vfDevice string

	vfs []pciDevice
}

func printPciDevInfo(device pciDevice, indent int, writer io.Writer) {
	fields := []string{
		fmt.Sprintf("addr: %s", device.addr),
		fmt.Sprintf("driver: %s", device.driver),
		fmt.Sprintf("vendor: %s", device.vendor),
		fmt.Sprintf("device: %s", device.device),
		fmt.Sprintf("ifnames: [ %s ]", strings.Join(device.kernelIfnames, ", ")),
	}

	fmt.Fprint(writer, strings.Repeat(" ", indent))
	fmt.Fprint(writer, strings.Join(fields, ","))
}

func printPfInfo(writer io.Writer, basePath string, device sriovDevice) {
	printPciDevInfo(device.pciDevice, 0, writer)
	fmt.Fprintf(writer, "\n vf count (actual): %s, ", device.numVfs)
	fmt.Fprintf(writer, "vf max: %s\n", device.totalVfs)

	if len(device.vfs) > 0 {
		fmt.Fprintln(writer, "  vfs: ")
	}

	for i, v := range device.vfs {
		fmt.Fprintf(writer, "  VF %d: ", i)
		printPciDevInfo(v, 2, writer)
		fmt.Fprintln(writer)
	}

	fmt.Fprintln(writer)
}

func getPciDevice(basePath, address string) (*pciDevice, error) {
	dev := pciDevice{addr: address}
	devicePath := path.Join(basePath, address)

	driver, err := os.Readlink(path.Join(devicePath, "driver"))
	if err != nil {
		return nil, err
	}

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

	dev.device = strings.ReplaceAll(string(device), "\n", "")

	ifnames, err := os.ReadDir(path.Join(devicePath, "net"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &dev, nil
		}
	}

	for _, i := range ifnames {
		dev.kernelIfnames = append(dev.kernelIfnames, i.Name())
	}

	return &dev, nil
}

func getSriovDevice(basePath, address string) (*sriovDevice, error) {
	devicePath := path.Join(basePath, address)
	pciDev, err := getPciDevice(basePath, address)
	if err != nil {
		return nil, err
	}

	dev := sriovDevice{pciDevice: *pciDev}

	numVfs, err := os.ReadFile(path.Join(devicePath, "sriov_numvfs"))
	if err != nil {
		return nil, err
	}

	dev.numVfs = strings.ReplaceAll(string(numVfs), "\n", "")

	totalVfs, err := os.ReadFile(path.Join(devicePath, "sriov_totalvfs"))
	if err != nil {
		return nil, err
	}

	dev.totalVfs = strings.ReplaceAll(string(totalVfs), "\n", "")

	vfDevice, err := os.ReadFile(path.Join(devicePath, "sriov_vf_device"))
	if err != nil {
		return nil, err
	}

	dev.vfDevice = strings.ReplaceAll(string(vfDevice), "\n", "")

	dirs, err := os.ReadDir(devicePath)
	if err != nil {
		return nil, err
	}

	n, err := strconv.Atoi(dev.numVfs)
	if err != nil {
		// no vfs, probably
		return &dev, nil
	}

	dev.vfs = make([]pciDevice, n)

	for _, d := range dirs {
		if !strings.HasPrefix(d.Name(), "virtfn") {
			continue
		}

		vfId := strings.ReplaceAll(d.Name(), "virtfn", "")
		i, err := strconv.Atoi(vfId)
		if err != nil {
			continue
		}

		vfPath, err := os.Readlink(path.Join(devicePath, d.Name()))
		if err != nil {
			return nil, err
		}

		vfAddr := path.Base(vfPath)

		p, err := getPciDevice(basePath, vfAddr)
		if err != nil {
			continue
		}

		dev.vfs[i] = *p
	}

	return &dev, nil
}
