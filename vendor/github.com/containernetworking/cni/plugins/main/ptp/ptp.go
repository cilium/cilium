// Copyright 2015 CNI authors
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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"

	"github.com/vishvananda/netlink"

	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/ipam"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/utils"
	"github.com/containernetworking/cni/pkg/version"
)

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

type NetConf struct {
	types.NetConf
	IPMasq bool `json:"ipMasq"`
	MTU    int  `json:"mtu"`
}

func setupContainerVeth(netns ns.NetNS, ifName string, mtu int, pr *current.Result) (*current.Interface, *current.Interface, error) {
	// The IPAM result will be something like IP=192.168.3.5/24, GW=192.168.3.1.
	// What we want is really a point-to-point link but veth does not support IFF_POINTOPONT.
	// Next best thing would be to let it ARP but set interface to 192.168.3.5/32 and
	// add a route like "192.168.3.0/24 via 192.168.3.1 dev $ifName".
	// Unfortunately that won't work as the GW will be outside the interface's subnet.

	// Our solution is to configure the interface with 192.168.3.5/24, then delete the
	// "192.168.3.0/24 dev $ifName" route that was automatically added. Then we add
	// "192.168.3.1/32 dev $ifName" and "192.168.3.0/24 via 192.168.3.1 dev $ifName".
	// In other words we force all traffic to ARP via the gateway except for GW itself.

	hostInterface := &current.Interface{}
	containerInterface := &current.Interface{}

	err := netns.Do(func(hostNS ns.NetNS) error {
		hostVeth, contVeth0, err := ip.SetupVeth(ifName, mtu, hostNS)
		if err != nil {
			return err
		}
		hostInterface.Name = hostVeth.Name
		hostInterface.Mac = hostVeth.HardwareAddr.String()
		containerInterface.Name = contVeth0.Name
		containerInterface.Mac = contVeth0.HardwareAddr.String()
		containerInterface.Sandbox = netns.Path()

		var firstV4Addr net.IP
		for _, ipc := range pr.IPs {
			// All addresses apply to the container veth interface
			ipc.Interface = 1

			if ipc.Address.IP.To4() != nil && firstV4Addr == nil {
				firstV4Addr = ipc.Address.IP
			}
		}

		pr.Interfaces = []*current.Interface{hostInterface, containerInterface}

		if firstV4Addr != nil {
			err = hostNS.Do(func(_ ns.NetNS) error {
				hostVethName := hostVeth.Name
				if err := ip.SetHWAddrByIP(hostVethName, firstV4Addr, nil /* TODO IPv6 */); err != nil {
					return fmt.Errorf("failed to set hardware addr by IP: %v", err)
				}

				return nil
			})
			if err != nil {
				return err
			}
		}

		if err = ipam.ConfigureIface(ifName, pr); err != nil {
			return err
		}

		if err := ip.SetHWAddrByIP(contVeth0.Name, firstV4Addr, nil /* TODO IPv6 */); err != nil {
			return fmt.Errorf("failed to set hardware addr by IP: %v", err)
		}

		// Re-fetch container veth to update attributes
		contVeth, err := netlink.LinkByName(ifName)
		if err != nil {
			return fmt.Errorf("failed to look up %q: %v", ifName, err)
		}

		for _, ipc := range pr.IPs {
			// Delete the route that was automatically added
			route := netlink.Route{
				LinkIndex: contVeth.Attrs().Index,
				Dst: &net.IPNet{
					IP:   ipc.Address.IP.Mask(ipc.Address.Mask),
					Mask: ipc.Address.Mask,
				},
				Scope: netlink.SCOPE_NOWHERE,
			}

			if err := netlink.RouteDel(&route); err != nil {
				return fmt.Errorf("failed to delete route %v: %v", route, err)
			}

			for _, r := range []netlink.Route{
				netlink.Route{
					LinkIndex: contVeth.Attrs().Index,
					Dst: &net.IPNet{
						IP:   ipc.Gateway,
						Mask: net.CIDRMask(32, 32),
					},
					Scope: netlink.SCOPE_LINK,
					Src:   ipc.Address.IP,
				},
				netlink.Route{
					LinkIndex: contVeth.Attrs().Index,
					Dst: &net.IPNet{
						IP:   ipc.Address.IP.Mask(ipc.Address.Mask),
						Mask: ipc.Address.Mask,
					},
					Scope: netlink.SCOPE_UNIVERSE,
					Gw:    ipc.Gateway,
					Src:   ipc.Address.IP,
				},
			} {
				if err := netlink.RouteAdd(&r); err != nil {
					return fmt.Errorf("failed to add route %v: %v", r, err)
				}
			}
		}

		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return hostInterface, containerInterface, nil
}

func setupHostVeth(vethName string, result *current.Result) error {
	// hostVeth moved namespaces and may have a new ifindex
	veth, err := netlink.LinkByName(vethName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", vethName, err)
	}

	for _, ipc := range result.IPs {
		maskLen := 128
		if ipc.Address.IP.To4() != nil {
			maskLen = 32
		}

		ipn := &net.IPNet{
			IP:   ipc.Gateway,
			Mask: net.CIDRMask(maskLen, maskLen),
		}
		addr := &netlink.Addr{IPNet: ipn, Label: ""}
		if err = netlink.AddrAdd(veth, addr); err != nil {
			return fmt.Errorf("failed to add IP addr (%#v) to veth: %v", ipn, err)
		}

		ipn = &net.IPNet{
			IP:   ipc.Address.IP,
			Mask: net.CIDRMask(maskLen, maskLen),
		}
		// dst happens to be the same as IP/net of host veth
		if err = ip.AddHostRoute(ipn, nil, veth); err != nil && !os.IsExist(err) {
			return fmt.Errorf("failed to add route on host: %v", err)
		}
	}

	return nil
}

func cmdAdd(args *skel.CmdArgs) error {
	conf := NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	if err := ip.EnableIP4Forward(); err != nil {
		return fmt.Errorf("failed to enable forwarding: %v", err)
	}

	// run the IPAM plugin and get back the config to apply
	r, err := ipam.ExecAdd(conf.IPAM.Type, args.StdinData)
	if err != nil {
		return err
	}
	// Convert whatever the IPAM result was into the current Result type
	result, err := current.NewResultFromResult(r)
	if err != nil {
		return err
	}

	if len(result.IPs) == 0 {
		return errors.New("IPAM plugin returned missing IP config")
	}

	netns, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %v", args.Netns, err)
	}
	defer netns.Close()

	hostInterface, containerInterface, err := setupContainerVeth(netns, args.IfName, conf.MTU, result)
	if err != nil {
		return err
	}

	if err = setupHostVeth(hostInterface.Name, result); err != nil {
		return err
	}

	if conf.IPMasq {
		chain := utils.FormatChainName(conf.Name, args.ContainerID)
		comment := utils.FormatComment(conf.Name, args.ContainerID)
		for _, ipc := range result.IPs {
			if err = ip.SetupIPMasq(&ipc.Address, chain, comment); err != nil {
				return err
			}
		}
	}

	result.DNS = conf.DNS
	result.Interfaces = []*current.Interface{hostInterface, containerInterface}

	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	conf := NetConf{}
	if err := json.Unmarshal(args.StdinData, &conf); err != nil {
		return fmt.Errorf("failed to load netconf: %v", err)
	}

	if err := ipam.ExecDel(conf.IPAM.Type, args.StdinData); err != nil {
		return err
	}

	if args.Netns == "" {
		return nil
	}

	// There is a netns so try to clean up. Delete can be called multiple times
	// so don't return an error if the device is already removed.
	// If the device isn't there then don't try to clean up IP masq either.
	var ipn *net.IPNet
	err := ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		var err error
		ipn, err = ip.DelLinkByNameAddr(args.IfName, netlink.FAMILY_V4)
		if err != nil && err == ip.ErrLinkNotFound {
			return nil
		}
		return err
	})

	if err != nil {
		return err
	}

	if ipn != nil && conf.IPMasq {
		chain := utils.FormatChainName(conf.Name, args.ContainerID)
		comment := utils.FormatComment(conf.Name, args.ContainerID)
		err = ip.TeardownIPMasq(ipn, chain, comment)
	}

	return err
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}
