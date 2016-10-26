//
// Copyright 2016 Authors of Cilium
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
//
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/addressing"
	cnc "github.com/cilium/cilium/common/client"
	"github.com/cilium/cilium/common/ipam"
	"github.com/cilium/cilium/common/plugins"
	"github.com/cilium/cilium/common/types"

	"github.com/appc/cni/pkg/version"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	l "github.com/op/go-logging"
	"github.com/vishvananda/netlink"
)

var log = l.MustGetLogger("cilium-net-cni")

func init() {
	common.SetupLOG(log, "DEBUG")

	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

type netConf struct {
	cniTypes.NetConf
	MTU int `json:"mtu"`
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.PluginSupports("0.1.0", "0.2.0"))
}

func loadNetConf(bytes []byte) (*netConf, error) {
	n := &netConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %s", err)
	}
	return n, nil
}

func removeIfFromNSIfExists(netNs ns.NetNS, ifName string) error {
	return netNs.Do(func(_ ns.NetNS) error {
		l, err := netlink.LinkByName(ifName)
		if err != nil {
			if strings.Contains(err.Error(), "Link not found") {
				return nil
			}
			return err
		}
		return netlink.LinkDel(l)
	})
}

func renameLink(curName, newName string) error {
	link, err := netlink.LinkByName(curName)
	if err != nil {
		return err
	}

	return netlink.LinkSetName(link, newName)
}

func addIPConfigToLink(ipConfig *ipam.IPConfig, link netlink.Link, ifName string) error {
	log.Debugf("Configuring link %+v/%s with %+v", link, ifName, ipConfig)

	addr := &netlink.Addr{IPNet: &ipConfig.IP}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add addr to %q: %v", ifName, err)
	}

	// Sort provided routes to make sure we apply any more specific
	// routes first which may be used as nexthops in wider routes
	sort.Sort(ipam.ByMask(ipConfig.Routes))

	for _, r := range ipConfig.Routes {
		log.Debugf("Adding route %+v", r)
		rt := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       &r.Destination,
			Gw:        r.NextHop,
		}

		if r.IsL2() {
			rt.Scope = netlink.SCOPE_LINK
		}

		if err := netlink.RouteAdd(rt); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add route '%s via %v dev %v': %v",
					r.Destination.String(), r.NextHop, ifName, err)
			}
		}
	}

	return nil
}

func configureIface(ifName string, config *ipam.IPAMRep) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to set %q UP: %v", ifName, err)
	}

	if config.IP4 != nil {
		if err := addIPConfigToLink(config.IP4, link, ifName); err != nil {
			return fmt.Errorf("error configuring IPv4: %s", err.Error())
		}
	}
	if config.IP6 != nil {
		if err := addIPConfigToLink(config.IP6, link, ifName); err != nil {
			return fmt.Errorf("error configuring IPv6: %s", err.Error())
		}
	}

	return nil
}

func createCNIReply(ipamConf *ipam.IPAMRep) error {
	v6Routes := []cniTypes.Route{}
	v4Routes := []cniTypes.Route{}
	for _, r := range ipamConf.IP6.Routes {
		newRoute := cniTypes.Route{
			Dst: r.Destination,
		}
		if r.NextHop != nil {
			newRoute.GW = r.NextHop
		}
		v6Routes = append(v6Routes, newRoute)
	}

	r := cniTypes.Result{
		IP6: &cniTypes.IPConfig{
			IP:      ipamConf.IP6.IP,
			Gateway: ipamConf.IP6.Gateway,
			Routes:  v6Routes,
		},
	}

	if ipamConf.IP4 != nil {
		for _, r := range ipamConf.IP4.Routes {
			newRoute := cniTypes.Route{
				Dst: r.Destination,
			}
			if r.NextHop != nil {
				newRoute.GW = r.NextHop
			}
			v4Routes = append(v4Routes, newRoute)
		}
		r.IP4 = &cniTypes.IPConfig{
			IP:      ipamConf.IP4.IP,
			Gateway: ipamConf.IP4.Gateway,
			Routes:  v4Routes,
		}
	}

	return r.Print()
}

func cmdAdd(args *skel.CmdArgs) error {
	n, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	log.Debugf("Args %s", args)

	c, err := cnc.NewDefaultClient()
	if err != nil {
		return fmt.Errorf("error while starting cilium-client: %s", err)
	}

	netNs, err := ns.GetNS(args.Netns)
	if err != nil {
		return fmt.Errorf("failed to open netns %q: %s", args.Netns, err)
	}
	defer netNs.Close()

	if err := removeIfFromNSIfExists(netNs, args.IfName); err != nil {
		return fmt.Errorf("failed removing interface %q from namespace %q: %s",
			args.IfName, args.Netns, err)
	}

	var ep types.Endpoint
	veth, peer, tmpIfName, err := plugins.SetupVeth(args.ContainerID, n.MTU, &ep)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if err = netlink.LinkDel(veth); err != nil {
				log.Warningf("failed to clean up veth %q: %s", veth.Name, err)
			}
		}
	}()

	if err = netlink.LinkSetNsFd(*peer, int(netNs.Fd())); err != nil {
		return fmt.Errorf("unable to move veth pair %q to netns: %s", peer, err)
	}

	err = netNs.Do(func(_ ns.NetNS) error {
		err := renameLink(tmpIfName, args.IfName)
		if err != nil {
			return fmt.Errorf("failed to rename %q to %q: %s", tmpIfName, args.IfName, err)
		}
		return nil
	})

	req := ipam.IPAMReq{}
	ipamConf, err := c.AllocateIP(ipam.CNIIPAMType, req)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil && ipamConf != nil {
			if ipamConf.IP6 != nil {
				req := ipam.IPAMReq{IP: &ipamConf.IP6.IP.IP}
				if err = c.ReleaseIP(ipam.CNIIPAMType, req); err != nil {
					log.Warningf("failed to release allocated IPv6 of container ID %q: %s", args.ContainerID, err)
				}
			}
			if ipamConf.IP4 != nil {
				req := ipam.IPAMReq{IP: &ipamConf.IP4.IP.IP}
				if err = c.ReleaseIP(ipam.CNIIPAMType, req); err != nil {
					log.Warningf("failed to release allocated IPv4 of container ID %q: %s", args.ContainerID, err)
				}
			}
		}
	}()

	if err = netNs.Do(func(_ ns.NetNS) error {
		return configureIface(args.IfName, ipamConf)
	}); err != nil {
		return err
	}

	ep.IPv6 = addressing.DeriveCiliumIPv6(ipamConf.IP6.IP.IP)
	if ipamConf.IP4 != nil {
		ep.IPv4 = addressing.DeriveCiliumIPv4(ipamConf.IP4.IP.IP)
	}
	ep.NodeIP = ipamConf.IP6.Gateway
	ep.DockerID = args.ContainerID
	ep.SetID()
	if err = c.EndpointJoin(ep); err != nil {
		return fmt.Errorf("unable to create eBPF map: %s", err)
	}

	return createCNIReply(ipamConf)
}

func cmdDel(args *skel.CmdArgs) error {
	c, err := cnc.NewDefaultClient()
	if err != nil {
		return fmt.Errorf("error while starting cilium-client: %s", err)
	}

	ep, err := c.EndpointGetByDockerID(args.ContainerID)
	if err != nil {
		return fmt.Errorf("error while retrieving endpoint from cilium daemon: %s", err)
	}
	if ep == nil {
		return fmt.Errorf("endpoint with container ID %s not found", args.ContainerID)
	}

	ipv6addr := ep.IPv6.IP()
	if err = c.ReleaseIP(ipam.CNIIPAMType, ipam.IPAMReq{IP: &ipv6addr}); err != nil {
		log.Warningf("failed to release allocated IPv6 of container ID %q: %s", args.ContainerID, err)
	}
	ipv4addr := ep.IPv4.IP()
	if ep.IPv4 != nil {
		if err = c.ReleaseIP(ipam.CNIIPAMType, ipam.IPAMReq{IP: &ipv4addr}); err != nil {
			log.Warningf("failed to release allocated IPv4 of container ID %q: %s", args.ContainerID, err)
		}
	}

	if err := c.EndpointLeave(ep.ID); err != nil {
		log.Warningf("leaving the endpoint failed: %s\n", err)
	}

	return ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		return plugins.DelLinkByName(args.IfName)
	})
}
