// Copyright 2017-2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package loader

import (
	"context"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command/exec"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"

	"github.com/vishvananda/netlink"
)

type baseDeviceMode string

const (
	flannelMode = baseDeviceMode("flannel")
	ipvlanMode  = baseDeviceMode("ipvlan")
	directMode  = baseDeviceMode("direct")

	libbpfFixupMsg = "struct bpf_elf_map fixup performed due to size mismatch!"
)

func replaceQdisc(ifName string) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	if err = netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("netlink: Replacing qdisc for %s failed: %s", ifName, err)
	} else {
		log.Debugf("netlink: Replacing qdisc for %s succeeded", ifName)
	}

	return nil
}

// replaceDatapath the qdisc and BPF program for a endpoint
func (l *Loader) replaceDatapath(ctx context.Context, ifName, objPath, progSec, progDirection string) error {
	err := replaceQdisc(ifName)
	if err != nil {
		return fmt.Errorf("Failed to replace Qdisc for %s: %s", ifName, err)
	}

	// FIXME: Replace cilium-map-migrate with Golang map migration
	cmd := exec.CommandContext(ctx, "cilium-map-migrate", "-s", objPath)
	cmd.Env = bpf.Environment()
	if _, err = cmd.CombinedOutput(log, true); err != nil {
		return err
	}
	defer func() {
		var retCode string
		if err == nil {
			retCode = "0"
		} else {
			retCode = "1"
		}
		args := []string{"-e", objPath, "-r", retCode}
		cmd := exec.CommandContext(ctx, "cilium-map-migrate", args...)
		cmd.Env = bpf.Environment()
		_, _ = cmd.CombinedOutput(log, true) // ignore errors
	}()

	// FIXME: replace exec with native call
	args := []string{"filter", "replace", "dev", ifName, progDirection,
		"prio", "1", "handle", "1", "bpf", "da", "obj", objPath,
		"sec", progSec,
	}
	cmd = exec.CommandContext(ctx, "tc", args...).WithFilters(libbpfFixupMsg)
	_, err = cmd.CombinedOutput(log, true)
	if err != nil {
		return fmt.Errorf("Failed to load tc filter: %s", err)
	}

	return nil
}

// graftDatapath replaces obj in tail call map
func graftDatapath(ctx context.Context, mapPath, objPath, progSec string) error {
	var err error

	// FIXME: Replace cilium-map-migrate with Golang map migration
	cmd := exec.CommandContext(ctx, "cilium-map-migrate", "-s", objPath)
	cmd.Env = bpf.Environment()
	if _, err = cmd.CombinedOutput(log, true); err != nil {
		return err
	}
	defer func() {
		var retCode string
		if err == nil {
			retCode = "0"
		} else {
			retCode = "1"
		}
		args := []string{"-e", objPath, "-r", retCode}
		cmd := exec.CommandContext(ctx, "cilium-map-migrate", args...)
		cmd.Env = bpf.Environment()
		_, _ = cmd.CombinedOutput(log, true) // ignore errors
	}()

	// FIXME: replace exec with native call
	// FIXME: only key 0 right now, could be made more flexible
	args := []string{"exec", "bpf", "graft", mapPath, "key", "0",
		"obj", objPath, "sec", progSec,
	}
	cmd = exec.CommandContext(ctx, "tc", args...).WithFilters(libbpfFixupMsg)
	_, err = cmd.CombinedOutput(log, true)
	if err != nil {
		return fmt.Errorf("Failed to graft tc object: %s", err)
	}

	return nil
}

// RemoveTCFilters removes all tc filters from the given interface.
// Direction is passed as netlink.HANDLE_MIN_{INGRESS,EGRESS} via tcDir.
func RemoveTCFilters(ifName string, tcDir uint32) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	filters, err := netlink.FilterList(link, tcDir)
	if err != nil {
		return err
	}

	for _, f := range filters {
		if err := netlink.FilterDel(f); err != nil {
			return err
		}
	}

	return nil
}

func setupDev(link netlink.Link) error {
	ifName := link.Attrs().Name

	if err := netlink.LinkSetUp(link); err != nil {
		log.WithError(err).WithField("device", ifName).Warn("Could not set up the link")
		return err
	}

	sysSettings := make([]sysctl.Setting, 0, 5)
	if option.Config.EnableIPv6 {
		sysSettings = append(sysSettings, sysctl.Setting{
			Name: fmt.Sprintf("net.ipv6.conf.%s.forwarding", ifName), Val: "1", IgnoreErr: false})
	}
	if option.Config.EnableIPv4 {
		sysSettings = append(sysSettings, []sysctl.Setting{
			{Name: fmt.Sprintf("net.ipv4.conf.%s.forwarding", ifName), Val: "1", IgnoreErr: false},
			{Name: fmt.Sprintf("net.ipv4.conf.%s.rp_filter", ifName), Val: "0", IgnoreErr: false},
			{Name: fmt.Sprintf("net.ipv4.conf.%s.accept_local", ifName), Val: "1", IgnoreErr: false},
			{Name: fmt.Sprintf("net.ipv4.conf.%s.send_redirects", ifName), Val: "0", IgnoreErr: false},
		}...)
	}
	if err := sysctl.ApplySettings(sysSettings); err != nil {
		return err
	}

	return nil
}

func setupDevs(links ...netlink.Link) error {
	for _, link := range links {
		if err := setupDev(link); err != nil {
			return err
		}
	}
	return nil
}

func setupVethPair(name, peerName string) error {
	// Create the veth pair if it doesn't exist.
	if _, err := netlink.LinkByName(name); err != nil {
		hostMac, err := mac.GenerateRandMAC()
		if err != nil {
			return err
		}
		peerMac, err := mac.GenerateRandMAC()
		if err != nil {
			return err
		}

		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{
				Name:         name,
				HardwareAddr: net.HardwareAddr(hostMac),
			},
			PeerName:         peerName,
			PeerHardwareAddr: net.HardwareAddr(peerMac),
		}
		if err := netlink.LinkAdd(veth); err != nil {
			return err
		}
	}

	veth, err := netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if err := setupDev(veth); err != nil {
		return err
	}
	peer, err := netlink.LinkByName(peerName)
	if err != nil {
		return err
	}
	if err := setupDev(peer); err != nil {
		return err
	}

	return nil
}

func setupIpvlan(name string, nativeLink netlink.Link) (*netlink.IPVlan, error) {
	hostLink, err := netlink.LinkByName(name)
	if err == nil {
		// Ignore the error.
		netlink.LinkDel(hostLink)
	}

	ipvlan := &netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        name,
			ParentIndex: nativeLink.Attrs().Index,
		},
		Mode: netlink.IPVLAN_MODE_L3,
	}
	if err := netlink.LinkAdd(ipvlan); err != nil {
		return nil, err
	}

	if err := setupDev(ipvlan); err != nil {
		return nil, err
	}

	return ipvlan, nil
}

// setupBaseDevice decides which and what kind of interfaces should be set up as
// the first step of datapath initialization, then performs the setup (and
// creation, if needed) of those interfaces. It returns two links and an error.
// By default, it sets up the veth pair - cilium_host and cilium_net.
// In flannel mode, it sets up the native interface used by flannel.
// In ipvlan mode, it creates the cilium_host ipvlan with the native device as a
// parent.
func setupBaseDevice(nativeDevs []netlink.Link, mode baseDeviceMode, mtu int) (netlink.Link, netlink.Link, error) {
	switch mode {
	case flannelMode:
		if err := setupDevs(nativeDevs...); err != nil {
			return nil, nil, err
		}
		return nativeDevs[0], nativeDevs[0], nil
	case ipvlanMode:
		ipvlan, err := setupIpvlan(defaults.HostDevice, nativeDevs[0])
		if err != nil {
			return nil, nil, err
		}
		if err := netlink.LinkSetMTU(ipvlan, mtu); err != nil {
			return nil, nil, err
		}

		return ipvlan, ipvlan, nil
	default:
		if err := setupVethPair(defaults.HostDevice, defaults.SecondHostDevice); err != nil {
			return nil, nil, err
		}

		linkHost, err := netlink.LinkByName(defaults.HostDevice)
		if err != nil {
			return nil, nil, err
		}
		linkNet, err := netlink.LinkByName(defaults.SecondHostDevice)
		if err != nil {
			return nil, nil, err
		}

		if err := netlink.LinkSetARPOff(linkHost); err != nil {
			return nil, nil, err
		}
		if err := netlink.LinkSetARPOff(linkNet); err != nil {
			return nil, nil, err
		}

		if err := netlink.LinkSetMTU(linkHost, mtu); err != nil {
			return nil, nil, err
		}
		if err := netlink.LinkSetMTU(linkNet, mtu); err != nil {
			return nil, nil, err
		}

		return linkHost, linkNet, nil
	}
}
