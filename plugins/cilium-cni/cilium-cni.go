// Copyright 2016-2017 Authors of Cilium
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
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/common/plugins"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/endpoint"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesVer "github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var (
	log = logrus.New()
)

func init() {
	log.Level = logrus.DebugLevel
	runtime.LockOSThread()
}

type CmdState struct {
	Endpoint  *models.EndpointChangeRequest
	IP6       addressing.CiliumIPv6
	IP6routes []plugins.Route
	IP4       addressing.CiliumIPv4
	IP4routes []plugins.Route
	Client    *client.Client
	HostAddr  *models.NodeAddressing
}

type netConf struct {
	cniTypes.NetConf
	MTU  int  `json:"mtu"`
	Args Args `json:"args"`
}

// Args contains arbitrary information a scheduler
// can pass to the cni plugin
type Args struct {
	Mesos Mesos `json:"org.apache.mesos,omitempty"`
}

// Mesos contains network-specific information from the scheduler to the cni plugin
type Mesos struct {
	NetworkInfo NetworkInfo `json:"network_info"`
}

// NetworkInfo supports passing only labels from mesos
type NetworkInfo struct {
	Name   string `json:"name"`
	Labels struct {
		Labels []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"labels,omitempty"`
	} `json:"labels,omitempty"`
}

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}

func IPv6IsEnabled(ipam *models.IPAM) bool {
	if ipam == nil || ipam.Endpoint.IPV6 == "" {
		return false
	}

	if ipam.HostAddressing != nil {
		return ipam.HostAddressing.IPV6.Enabled
	}

	return true
}

func IPv4IsEnabled(ipam *models.IPAM) bool {
	if ipam == nil || ipam.Endpoint.IPV4 == "" {
		return false
	}

	if ipam.HostAddressing != nil {
		return ipam.HostAddressing.IPV4.Enabled
	}

	return true
}

func loadNetConf(bytes []byte) (*netConf, string, error) {
	n := &netConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %s", err)
	}
	return n, n.CNIVersion, nil
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

func releaseIP(client *client.Client, ip string) {
	if ip != "" {
		if err := client.IPAMReleaseIP(ip); err != nil {
			log.Warningf("Unable to release IP %s: %s", ip, err)
		}
	}
}

func releaseIPs(client *client.Client, addr *models.EndpointAddressing) {
	releaseIP(client, addr.IPV6)
	releaseIP(client, addr.IPV4)
}

func addIPConfigToLink(ip addressing.CiliumIP, routes []plugins.Route, link netlink.Link, ifName string) error {
	log.Debugf("Configuring link %+v/%s with %s", link, ifName, ip.String())

	addr := &netlink.Addr{IPNet: ip.EndpointPrefix()}
	if err := netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add addr to %q: %v", ifName, err)
	}

	// Sort provided routes to make sure we apply any more specific
	// routes first which may be used as nexthops in wider routes
	sort.Sort(plugins.ByMask(routes))

	for _, r := range routes {
		log.Debugf("Adding route %+v", r)
		rt := &netlink.Route{
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       &r.Prefix,
		}

		if r.Nexthop == nil {
			rt.Scope = netlink.SCOPE_LINK
		} else {
			rt.Gw = *r.Nexthop
		}

		if err := netlink.RouteAdd(rt); err != nil {
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add route '%s via %v dev %v': %v",
					r.Prefix.String(), r.Nexthop, ifName, err)
			}
		}
	}

	return nil
}

func configureIface(ipam *models.IPAM, ifName string, state *CmdState) (string, error) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return "", fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return "", fmt.Errorf("failed to set %q UP: %v", ifName, err)
	}

	if IPv4IsEnabled(ipam) {
		if err := addIPConfigToLink(state.IP4, state.IP4routes, link, ifName); err != nil {
			return "", fmt.Errorf("error configuring IPv4: %s", err.Error())
		}
	}

	if IPv6IsEnabled(ipam) {
		if err := addIPConfigToLink(state.IP6, state.IP6routes, link, ifName); err != nil {
			return "", fmt.Errorf("error configuring IPv6: %s", err.Error())
		}
	}

	if link.Attrs() != nil {
		return link.Attrs().HardwareAddr.String(), nil
	}

	return "", nil
}

func newCNIRoute(r plugins.Route) *cniTypes.Route {
	rt := &cniTypes.Route{
		Dst: r.Prefix,
	}
	if r.Nexthop != nil {
		rt.GW = *r.Nexthop
	}

	return rt
}

func prepareIP(ipAddr string, isIPv6 bool, state *CmdState) (*cniTypesVer.IPConfig, []*cniTypes.Route, error) {
	var (
		routes  []plugins.Route
		err     error
		gw      string
		version string
		ip      addressing.CiliumIP
	)

	if isIPv6 {
		if state.IP6, err = addressing.NewCiliumIPv6(ipAddr); err != nil {
			return nil, nil, err
		}
		if state.IP6routes, err = plugins.IPv6Routes(state.HostAddr); err != nil {
			return nil, nil, err
		}
		routes = state.IP6routes
		ip = state.IP6
		gw = plugins.IPv6Gateway(state.HostAddr)
		version = "6"
	} else {
		if state.IP4, err = addressing.NewCiliumIPv4(ipAddr); err != nil {
			return nil, nil, err
		}
		if state.IP4routes, err = plugins.IPv4Routes(state.HostAddr); err != nil {
			return nil, nil, err
		}
		routes = state.IP4routes
		ip = state.IP4
		gw = plugins.IPv4Gateway(state.HostAddr)
		version = "4"
	}

	rt := []*cniTypes.Route{}
	for _, r := range routes {
		rt = append(rt, newCNIRoute(r))
	}

	gwIP := net.ParseIP(gw)
	if gwIP == nil {
		return nil, nil, fmt.Errorf("Invalid gateway address: %s", gw)
	}

	return &cniTypesVer.IPConfig{
		Address: *ip.EndpointPrefix(),
		Gateway: gwIP,
		Version: version,
		// We only configure one interface for each run, thus, the
		// interface index from the Result interface list will be always
		// 0.
		Interface: 0,
	}, rt, nil
}

func cmdAdd(args *skel.CmdArgs) error {
	log.Debugf("ADD %s", args)

	n, cniVersion, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	client, err := client.NewDefaultClient()
	if err != nil {
		return fmt.Errorf("unable to connect to Cilium daemon: %s", err)
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

	addLabels := models.Labels{}

	for _, label := range n.Args.Mesos.NetworkInfo.Labels.Labels {
		addLabels = append(addLabels, fmt.Sprintf("%s:%s=%s", labels.LabelSourceMesos, label.Key, label.Value))
	}

	ep := &models.EndpointChangeRequest{
		ContainerID: args.ContainerID,
		Labels:      addLabels,
		State:       models.EndpointStateWaitingForIdentity,
		Addressing:  &models.EndpointAddressing{},
	}

	veth, peer, tmpIfName, err := plugins.SetupVeth(ep.ContainerID, n.MTU, ep)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if err = netlink.LinkDel(veth); err != nil {
				log.Warningf("failed to clean up and delete veth %q: %s", veth.Name, err)
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

	ipam, err := client.IPAMAllocate("")
	if err != nil {
		return err
	}

	if ipam.Endpoint == nil {
		return fmt.Errorf("Invalid IPAM response, missing addressing")
	}

	ep.Addressing.IPV6 = ipam.Endpoint.IPV6
	ep.Addressing.IPV4 = ipam.Endpoint.IPV4

	// release addresses on failure
	defer func() {
		if err != nil {
			releaseIPs(client, ep.Addressing)
		}
	}()

	if err = plugins.SufficientAddressing(ipam.HostAddressing); err != nil {
		return fmt.Errorf("%s", err)
	}

	state := CmdState{
		Endpoint: ep,
		Client:   client,
		HostAddr: ipam.HostAddressing,
	}

	res := &cniTypesVer.Result{}

	if IPv6IsEnabled(ipam) {
		ipConfig, routes, err := prepareIP(ep.Addressing.IPV6, true, &state)
		if err != nil {
			return err
		}
		ep.ID = int64(state.IP6.EndpointID())
		res.IPs = append(res.IPs, ipConfig)
		res.Routes = append(res.Routes, routes...)
	} else {
		return fmt.Errorf("IPAM did not provide required IPv6 address")
	}

	if IPv4IsEnabled(ipam) {
		ipConfig, routes, err := prepareIP(ep.Addressing.IPV4, false, &state)
		if err != nil {
			return err
		}
		res.IPs = append(res.IPs, ipConfig)
		res.Routes = append(res.Routes, routes...)
	}

	var macAddrStr string
	// FIXME: use nsenter
	if err = netNs.Do(func(_ ns.NetNS) error {
		out, err := exec.Command("sysctl", "-w", "net.ipv6.conf.all.disable_ipv6=0").CombinedOutput()
		if err != nil {
			log.Warnf("Error while enabling IPv6 on all interfaces: %s", err)
		}
		log.Debugf("Enabling IPv6 command output: %s", out)
		macAddrStr, err = configureIface(ipam, args.IfName, &state)
		return err
	}); err != nil {
		return err
	}

	res.Interfaces = append(res.Interfaces, &cniTypesVer.Interface{
		Name:    args.IfName,
		Mac:     macAddrStr,
		Sandbox: "/proc/" + args.Netns + "/ns/net",
	})

	if err = client.EndpointCreate(ep); err != nil {
		return fmt.Errorf("Unable to create endpoint: %s", err)
	}

	return cniTypes.PrintResult(res, cniVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	log.Debugf("DEL %s", args)

	client, err := client.NewDefaultClient()
	if err != nil {
		return fmt.Errorf("unable to connect to Cilium daemon: %s", err)
	}

	id := endpoint.NewID(endpoint.ContainerIdPrefix, args.ContainerID)
	if ep, err := client.EndpointGet(id); err != nil {
		// Ignore endpoints not found
		log.Debugf("unable to find endpoint %s: %s", id, err)
		return nil
	} else if ep == nil {
		log.Debugf("unable to find endpoint %s: %s", id, err)
		return nil
	} else {
		releaseIPs(client, ep.Addressing)
	}

	if err := client.EndpointDelete(id); err != nil {
		log.Warningf("Deletion of endpoint failed: %s", err)
	}

	return ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		return plugins.DelLinkByName(args.IfName)
	})
}
