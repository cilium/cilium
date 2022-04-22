// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"net"

	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesVer "github.com/containernetworking/cni/pkg/types/040"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

// TODO: define in pkg/k8s/apis/cilium.io
const (
	networkInterfaceAttach               = "io.cilium.network-interface.attach"
	networkInterfaceAttachPrefix         = labels.LabelSourceK8s + ":" + networkInterfaceAttach + "/"
	networkInterfaceAttachRealized       = networkInterfaceAttach + ".realized"
	networkInterfaceAttachRealizedPrefix = labels.LabelSourceCNI + ":" + networkInterfaceAttachRealized + "/"
)

func getMultiHomingEndpointID(containerID, hostIfaceName, attachIfaceName string) string {
	return containerID + "+" + hostIfaceName + "=" + attachIfaceName
}

func getHostIfaceAddrs(hostIfaceName string) (net.IP, net.IP, error) {
	hostLink, err := netlink.LinkByName(hostIfaceName)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get link for host-side interface %q: %w", hostIfaceName, err)
	}

	v4Addrs, err := netlink.AddrList(hostLink, netlink.FAMILY_V4)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get IPv4 address list for host-side interface %q: %w", hostIfaceName, err)
	}

	v6Addrs, err := netlink.AddrList(hostLink, netlink.FAMILY_V6)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get IPv6 address list for host-side interface %q: %w", hostIfaceName, err)
	}

	var v4Addr, v6Addr net.IP
	if len(v4Addrs) > 0 {
		v4Addr = v4Addrs[0].IP.To4()
	}
	if len(v6Addrs) > 0 {
		v6Addr = v6Addrs[0].IP.To16()
	}
	return v4Addr, v6Addr, nil
}

func getMultiHomingPodRoute(ip net.IP, mtu int) *route.Route {
	// XXX: Hard-code mask for now, this info should come from IPAM
	var mask net.IPMask
	if ip.To4() != nil {
		mask = net.IPv4Mask(255, 255, 255, 0)
	} else {
		mask = net.CIDRMask(96, 128)
	}
	return &route.Route{
		Prefix: net.IPNet{
			IP:   ip.Mask(mask),
			Mask: mask,
		},
		Nexthop: &ip,
		MTU:     mtu,
	}
}

func installMultiHomingHostRoute(podIP net.IP) error {
	link, err := netlink.LinkByName(defaults.HostDevice)
	if err != nil {
		return fmt.Errorf("failed to get link %s: %w", defaults.HostDevice, err)
	}

	// host netns route:
	// <pod IP>/24 dev cilium_host
	var mask net.IPMask
	if podIP.To4() != nil {
		mask = net.CIDRMask(24, 32)
	} else {
		mask = net.CIDRMask(128, 128)
	}
	r := &netlink.Route{
		Dst: &net.IPNet{
			IP:   podIP,
			Mask: mask,
		},
		LinkIndex: link.Attrs().Index,
	}
	err = netlink.RouteAdd(r)
	if err != nil {
		return fmt.Errorf("failed to install multi-homing host route: %w", err)
	}
	return nil
}

func attachInterfaceInPod(
	c *client.Client,
	cniArgs types.ArgsSpec,
	args *skel.CmdArgs,
	conf *models.DaemonConfigurationStatus,
	hostIfaceName, attachIfaceName string,
	podIPv4, podIPv6 net.IP,
	netNs ns.NetNS,
	logger *logrus.Entry) (*cniTypesVer.Result, error) {
	logger.Debugf("Attaching interface %q in pod to host interface %q", attachIfaceName, hostIfaceName)

	labelName := networkInterfaceAttachRealizedPrefix + hostIfaceName
	epLabels := labels.Labels{
		labelName: labels.NewLabel(labelName, attachIfaceName, labels.LabelSourceCNI),
	}
	epID := getMultiHomingEndpointID(args.ContainerID, hostIfaceName, attachIfaceName)
	ep := &models.EndpointChangeRequest{
		ContainerID:   epID,
		InterfaceName: hostIfaceName,
		Labels:        epLabels.GetModel(),
		State:         models.EndpointStateWaitingForIdentity,
		Addressing:    &models.AddressPair{},
		K8sPodName:    string(cniArgs.K8S_POD_NAME),
		K8sNamespace:  string(cniArgs.K8S_POD_NAMESPACE),
	}

	veth, peer, tmpIfName, err := connector.SetupVeth(epID, int(conf.DeviceMTU), ep)
	if err != nil {
		return nil, fmt.Errorf("unable to set up additional veth on host side: %w", err)
	}
	defer func() {
		if err != nil {
			if err2 := netlink.LinkDel(veth); err2 != nil {
				logger.WithError(err2).WithField(logfields.Veth, veth.Name).Warn("failed to clean up and delete additional veth")
			}
		}
	}()

	if err = netlink.LinkSetNsFd(peer, int(netNs.Fd())); err != nil {
		return nil, fmt.Errorf("unable to move additional veth pair '%v' to netns: %w", peer, err)
	}

	_, _, err = connector.SetupVethRemoteNs(netNs, tmpIfName, attachIfaceName)
	if err != nil {
		return nil, fmt.Errorf("unable to set up additional veth on container side: %w", err)
	}

	logger.Debugf("Successfully set up additional veth pair")

	// XXX: use primary pod address and modify it for PoC. In the final implementation this
	// should come from separate IPAM pool via IPAMAllocate below.
	var hasIPv4, hasIPv6 bool
	if podIPv4.To4() != nil {
		primary := make(net.IP, len(podIPv4))
		copy(primary, podIPv4)
		podIPv4.To4()[1] += 1
		hasIPv4 = true
		logger.WithFields(logrus.Fields{
			"primary":   primary,
			"secondary": podIPv4,
		}).Debug("Derived secondary pod IPv4 address from primary pod IPv4 address")
	}
	if podIPv6.To16() != nil {
		primary := make(net.IP, len(podIPv6))
		copy(primary, podIPv6)
		// XXX: disable IPv6 for now
		// hasIPv6 = true
		logger.WithFields(logrus.Fields{
			"primary":   primary,
			"secondary": podIPv6,
		}).Debug("Derived secondary pod IPv6 address from primary pod IPv6 address")
	}

	logger.WithFields(logrus.Fields{
		"ip":  podIPv4,
		"len": len(podIPv4),
	}).Debug("Got pod IPv4")

	/*
		podName := string(cniArgs.K8S_POD_NAMESPACE) + "/" + string(cniArgs.K8S_POD_NAME) + "+" + attachIfaceName
		ipam, err := c.IPAMAllocate("", podName, true)
		if err != nil {
			return nil, fmt.Errorf("unable to allocate additional interface IP via local cilium agent: %w", err)
		}

		if ipam == nil || ipam.Address == nil {
			return nil, errors.New("invalid IPAM response, missing addressing")
		}

		// XXX: ignore host addressing information (needs own IPAM mode for additional interfaces)
		ipam.HostAddressing = nil

		// release addresses on failure
		defer func() {
			if err != nil {
				releaseIP(c, ipam.Address.IPV4)
				releaseIP(c, ipam.Address.IPV6)
			}
		}()
	*/

	state := CmdState{
		Endpoint: ep,
		Client:   c,
		// XXX: Fake for now, this needs to come from IPAM in the future
		HostAddr: &models.NodeAddressing{
			IPV4: &models.NodeAddressingElement{
				Enabled: hasIPv4,
				IP:      podIPv4.String(),
			},
			IPV6: &models.NodeAddressingElement{
				Enabled: hasIPv6,
				IP:      podIPv6.String(),
			},
		},
	}

	res := &cniTypesVer.Result{}

	var (
		ipConfig *cniTypesVer.IPConfig
		routes   []*cniTypes.Route
	)

	if hasIPv6 {
		ep.Addressing.IPV6 = podIPv6.String()

		mtu := int(conf.RouteMTU)
		ipConfig, routes, err = prepareIP(ep.Addressing.IPV6, true, &state, mtu)
		if err != nil {
			return nil, fmt.Errorf("unable to prepare IPv6 addressing for %q: %s", ep.Addressing.IPV6, err)
		}

		// TODO: address & netmask (?) should come from IPAM. Might also want a separate MTU.
		podRoute := getMultiHomingPodRoute(podIPv6, mtu)
		state.IP6routes = append(state.IP6routes, *podRoute)
		res.IPs = append(res.IPs, ipConfig)
		res.Routes = append(res.Routes, routes...)
		res.Routes = append(res.Routes, newCNIRoute(podRoute))

		if err := installMultiHomingHostRoute(podIPv6); err != nil {
			return nil, fmt.Errorf("unable to install multi-homing host IPv6 routes: %w", err)
		}
	}

	if hasIPv4 {
		ep.Addressing.IPV4 = podIPv4.String()

		mtu := int(conf.RouteMTU)
		ipConfig, routes, err = prepareIP(ep.Addressing.IPV4, false, &state, mtu)
		if err != nil {
			return nil, fmt.Errorf("unable to prepare IPv4 addressing for %q: %s", ep.Addressing.IPV4, err)
		}

		// TODO: address & netmask (?) should come from IPAM. Might also want a separate MTU.
		podRoute := getMultiHomingPodRoute(podIPv4, mtu)
		state.IP4routes = append(state.IP4routes, *podRoute)
		res.IPs = append(res.IPs, ipConfig)
		res.Routes = append(res.Routes, routes...)
		res.Routes = append(res.Routes, newCNIRoute(podRoute))

		if err := installMultiHomingHostRoute(podIPv4); err != nil {
			return nil, fmt.Errorf("unable to install multi-homing host IPv4 routes: %w", err)
		}
	}

	var macAddrStr string
	if err = netNs.Do(func(_ ns.NetNS) error {
		macAddrStr, err = configureIface(hasIPv4, hasIPv6, attachIfaceName, &state)
		return err
	}); err != nil {
		return nil, fmt.Errorf("unable to configure additional interface %s in container namespace: %w", attachIfaceName, err)
	}

	logger.Debugf("Successfully configured interface %q", attachIfaceName)

	res.Interfaces = append(res.Interfaces, &cniTypesVer.Interface{
		Name:    attachIfaceName,
		Mac:     macAddrStr,
		Sandbox: netNs.Path(),
	})

	// Add to the result the Interface as index of Interfaces
	for i := range res.Interfaces {
		res.IPs[i].Interface = cniTypesVer.Int(i)
	}

	// Specify that endpoint must be regenerated synchronously. See GH-4409.
	ep.SyncBuildEndpoint = true
	if err = c.EndpointCreate(ep); err != nil {
		logger.WithError(err).WithField(logfields.ContainerID, ep.ContainerID).Warn("Unable to create additional endpoint")
		return nil, fmt.Errorf("Unable to create additional endpoint: %w", err)
	}

	logger.WithField(logfields.ContainerID, ep.ContainerID).Debug("Additional endpoint successfully created")

	return res, nil
}
