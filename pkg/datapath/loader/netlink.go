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
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
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
		sysctl.Enable(fmt.Sprintf("net.ipv6.conf.%s.forwarding", ifName))
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
	link, err := netlink.LinkByName(name)
	if err != nil {
		hostMac, err := mac.GenerateRandMAC()
		if err != nil {
			return err
		}
		peerMac, err := mac.GenerateRandMAC()
		if err != nil {
			return err
		}

		// Ignore the error.
		netlink.LinkDel(link)

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

	// for _, iface := range ifaces {
	// 	if err := setupDev(link); err != nil {
	// 		return err
	// 	}
	// }

	return nil
}

func setupIpvlanSlave(name string, nativeLink netlink.Link) (*netlink.IPVlan, error) {
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

func setupBaseDevice(nativeDevs []netlink.Link, mode string, mtu int) error {
	switch mode {
	case "flannel":
		if err := setupDevs(nativeDevs...); err != nil {
			return err
		}
	case "ipvlan":
		ciliumHostlink, err := netlink.LinkByName("cilium_host")
		if err != nil {
			return err
		}

		ipvlan, err := setupIpvlanSlave("cilium_host", nativeDevs[0])
		if err != nil {
			return err
		}
		if err := netlink.LinkSetMTU(ipvlan, mtu); err != nil {
			return err
		}
	default:
		if err := setupVethPair("cilium_host", "cilium_net"); err != nil {
			return err
		}

		link1, err := netlink.LinkByName("cilium_host")
		if err != nil {
			return err
		}
		link2, err := netlink.LinkByName("cilium_net")
		if err != nil {
			return err
		}

		if err := netlink.LinkSetARPOff(link1); err != nil {
			return err
		}
		if err := netlink.LinkSetARPOff(link2); err != nil {
			return err
		}

		if err := netlink.LinkSetMTU(link1, mtu); err != nil {
			return err
		}
		if err := netlink.LinkSetMTU(link2, mtu); err != nil {
			return err
		}
	}

	return nil
}

// moveLocalRulesAf moves the local table lookup rule from priority 0 to 100 so
// we can insert the cilium ip rules before the local table. It is strictly
// required to add the new local rule before deleting the old one as otherwise
// local addresses will not be reachable for a short period of time.
func moveLocalRulesAf(family int) error {
	filter1 := netlink.NewRule()
	filter1.Priority = 100
	filter1.Table = unix.RT_TABLE_LOCAL

	rules1, err := netlink.RuleListFiltered(family, filter1, 0)
	if err != nil {
		return err
	}

	if len(rules1) == 0 {
		rule := netlink.NewRule()
		rule.Priority = 100
		rule.Table = unix.RT_TABLE_LOCAL

		if err := netlink.RuleAdd(rule); err != nil {
			return err
		}
	}

	filter2 := netlink.NewRule()
	filter2.Priority = 0
	filter2.Table = unix.RT_TABLE_LOCAL

	rules2, err := netlink.RuleListFiltered(family, filter2, 0)
	if err != nil {
		return err
	}

	for _, ruleToDel := range rules2 {
		// Ignore the error.
		netlink.RuleDel(&ruleToDel)
	}

	// Check if the move of the local table move was successful and restore
	// it otherwise.
	filter3 := netlink.NewRule()
	filter3.Table = unix.RT_TABLE_LOCAL

	rules3, err := netlink.RuleListFiltered(family, filter3, 0)
	if err != nil {
		return err
	}

	if len(rules3) == 0 {
		rule := netlink.NewRule()
		rule.Priority = 0
		rule.Table = unix.RT_TABLE_LOCAL

		if err := netlink.RuleAdd(rule); err != nil {
			return err
		}

		filter4 := netlink.NewRule()
		filter4.Priority = 100
		filter4.Table = unix.RT_TABLE_LOCAL

		rules4, err := netlink.RuleListFiltered(family, filter4, 0)
		if err != nil {
			return err
		}

		for _, ruleToDel := range rules4 {
			if err := netlink.RuleDel(&ruleToDel); err != nil {
				return err
			}
		}

		return fmt.Errorf("")
	}

	return nil
}

func moveLocalRules() error {
	if option.Config.EnableIPv4 {
		if err := moveLocalRulesAf(4); err != nil {
			return err
		}
	}
	if option.Config.EnableIPv6 {
		if err := moveLocalRulesAf(6); err != nil {
			return err
		}
	}
	return nil
}

const (
	ProxyRtTable   = 2005
	ToProxyRtTable = 2004
)

func setupProxyRules(mode, hostDev1, hostDev2 string) error {
	switch mode {
	case "ipvlan":
		return nil
	}

	ruleFromIngress := netlink.NewRule()
	ruleFromIngress.Priority = 10
	ruleFromIngress.Table = ProxyRtTable
	ruleFromIngress.Mark = 0xA00
	ruleFromIngress.Mask = 0xF00

	ruleToProxy := netlink.NewRule()
	ruleToProxy.Priority = 9
	ruleToProxy.Table = ToProxyRtTable
	ruleToProxy.Mark = 0x200
	ruleToProxy.Mask = 0xF00

	if option.Config.EnableIPv4 {
		rules, err := netlink.RuleListFiltered(4, ruleToProxy, 0)
		if err != nil {
			return err
		}

		if len(rules) == 0 {
			if err := netlink.RuleAdd(ruleToProxy); err != nil {
				return err
			}
		}

		switch mode {
		case "routed":
			rules2, err := netlink.RuleListFiltered(4, ruleFromIngress, 0)
			if err != nil {
				return err
			}

			if len(rules2) > 0 {
				if err := netlink.RuleDel(ruleFromIngress); err != nil {
					return err
				}
			}
		default:
			rules2, err := netlink.RuleListFiltered(4, ruleToProxy, 0)
			if err != nil {
				return err
			}

			if len(rules2) == 0 {
				if err := netlink.RuleDel(ruleToProxy); err != nil {
					return err
				}
			}
		}
	} else {
		// Ignore errors.
		netlink.RuleDel(ruleToProxy)
		netlink.RuleDel(ruleFromIngress)
	}

	// flannel might not have an IPv6 address.
	switch mode {
	case "flannel":
	default:
		if option.Config.EnableIPv6 {
			rules, err := netlink.RuleListFiltered(6, ruleToProxy, 0)
			if err != nil {
				return err
			}

			if len(rules) == 0 {
				if err := netlink.RuleAdd(ruleToProxy); err != nil {
					return err
				}

				switch mode {
				case "routed":
					rules2, err := netlink.RuleListFiltered(6, ruleFromIngress, 0)
					if err != nil {
						return err
					}

					if len(rules2) > 0 {
						if err := netlink.RuleDel(ruleFromIngress); err != nil {
							return err
						}
					}
				default:
					rules2, err := netlink.RuleListFiltered(6, ruleFromIngress, 0)
					if err != nil {
						return err
					}

					if len(rules2) == 0 {
						if err := netlink.RuleAdd(ruleFromIngress); err != nil {
							return err
						}
					}
				}
			}

			hostLink1, err := netlink.LinkByName(hostDev1)
			if err != nil {
				return err
			}
			hostLink2, err := netlink.LinkByName(hostDev2)
			if err != nil {
				return err
			}
			addrs, err := netlink.AddrList(hostLink2, 6)
			if err != nil {
				return err
			}

			if len(addrs) > 0 {
				route := netlink.Route{
					LinkIndex: hostLink2.Attrs().Index,
					Table:     ToProxyRtTable,
					Type:      unix.RTN_LOCAL,
				}
				netlink.RouteReplace(&route)

				switch mode {
				case "routed":
					route2 := netlink.Route{
						LinkIndex: hostLink1.Attrs().Index,
						Dst:       addrs[0].IPNet, // TODO: /128
						Table:     ProxyRtTable,
					}
					route3 := netlink.Route{
						LinkIndex: hostLink1.Attrs().Index,
						Dst:       addrs[0].IPNet, // via?
						Table:     ProxyRtTable,
					}
					// Ignore errors.
					netlink.RouteDel(&route2)
					netlink.RouteDel(&route3)
				default:
					route2 := netlink.Route{
						LinkIndex: hostLink1.Attrs().Index,
						Dst:       addrs[0].IPNet, // TODO: /128
						Table:     ProxyRtTable,
					}
					route3 := netlink.Route{
						LinkIndex: hostLink1.Attrs().Index,
						Dst:       addrs[0].IPNet, // via?
						Table:     ProxyRtTable,
					}
					netlink.RouteReplace(&route2)
					netlink.RouteReplace(&route3)
				}
			}
		} else {
			// Ignore errors.
			netlink.RuleDel(ruleToProxy)
			netlink.RuleDel(ruleFromIngress)
		}
	}

	return nil
}

func mac2array(mac net.HardwareAddr) string {
	s := "{"
	s += fmt.Sprintf("0x%x", mac[0])
	for _, b := range mac[1:] {
		s += ","
		s += fmt.Sprintf("0x%x", b)
	}
	s += "}"

	return s
}
