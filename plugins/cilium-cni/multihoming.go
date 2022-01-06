// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"net"
	"net/netip"
	"sort"

	"github.com/containernetworking/cni/pkg/skel"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	ciliumip "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

// TODO: define in pkg/k8s/apis/cilium.io
const (
	secondaryNetworkAttach               = "io.cilium.secondary-network.attach"
	secondaryNetworkAttachPrefix         = labels.LabelSourceK8s + ":" + secondaryNetworkAttach + "/"
	secondaryNetworkAttachRealized       = secondaryNetworkAttach + ".realized"
	secondaryNetworkAttachRealizedPrefix = labels.LabelSourceCNI + ":" + secondaryNetworkAttachRealized + "/"
)

func getMultiHomingEndpointID(containerID, networkName, attachIfaceName string) string {
	return containerID + "+" + networkName + "=" + attachIfaceName
}

func getMultiHomingPodRoute(ip netip.Addr, mtu int) *route.Route {
	// XXX: Hard-code mask for now, this info should come from IPAM
	var mask net.IPMask
	nextHop := ciliumip.IPFromAddr(ip)
	if ip.Is4() {
		mask = net.IPv4Mask(255, 255, 255, 0)
	} else {
		mask = net.CIDRMask(96, 128)
	}
	return &route.Route{
		Prefix: net.IPNet{
			IP:   nextHop.Mask(mask),
			Mask: mask,
		},
		Nexthop: &nextHop,
		MTU:     mtu,
	}
}

func attachToMultiHomingNetwork(
	c *client.Client,
	cniArgs types.ArgsSpec,
	args *skel.CmdArgs,
	conf *models.DaemonConfigurationStatus,
	networkName string,
	networks []string,
	attachIfaceName string,
	podIPv4, podIPv6 netip.Addr,
	netNs ns.NetNS,
	logger *logrus.Entry) (*cniTypesVer.Result, error) {
	logger.Debugf("Attaching interface %q in pod to network %q", attachIfaceName, networkName)

	labelName := secondaryNetworkAttachRealizedPrefix + networkName
	epLabels := labels.Labels{
		labelName: labels.NewLabel(labelName, attachIfaceName, labels.LabelSourceCNI),
	}
	epID := getMultiHomingEndpointID(args.ContainerID, networkName, attachIfaceName)
	st := models.EndpointStateWaitingDashForDashIdentity
	ep := &models.EndpointChangeRequest{
		ContainerID:   epID,
		InterfaceName: attachIfaceName,
		Labels:        epLabels.GetModel(),
		State:         &st,
		Addressing:    &models.AddressPair{},
		K8sPodName:    string(cniArgs.K8S_POD_NAME),
		K8sNamespace:  string(cniArgs.K8S_POD_NAMESPACE),
	}

	veth, peer, tmpIfName, err := connector.SetupVeth(epID, int(conf.DeviceMTU), 0, 0, ep)
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
	if podIPv4.Is4() {
		primary := podIPv4
		s := podIPv4.As4()
		s[1] += byte(sort.SearchStrings(networks, networkName) + 1)
		podIPv4 = netip.AddrFrom4(s)
		hasIPv4 = true
		logger.WithFields(logrus.Fields{
			"primary":   primary,
			"secondary": podIPv4,
		}).Debug("Derived secondary pod IPv4 address from primary pod IPv4 address")
	}
	if podIPv6.Is6() {
		primary := podIPv6
		// XXX: disable IPv6 for now
		// hasIPv6 = true
		logger.WithFields(logrus.Fields{
			"primary":   primary,
			"secondary": podIPv6,
		}).Debug("Derived secondary pod IPv6 address from primary pod IPv6 address")
	}

	logger.WithFields(logrus.Fields{
		"ip": podIPv4,
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
		ipConfig, routes, err = prepareIP(ep.Addressing.IPV6, &state, mtu)
		if err != nil {
			return nil, fmt.Errorf("unable to prepare IPv6 addressing for %q: %s", ep.Addressing.IPV6, err)
		}

		// TODO: address & netmask (?) should come from IPAM. Might also want a separate MTU.
		podRoute := getMultiHomingPodRoute(podIPv6, mtu)
		state.IP6routes = append(state.IP6routes, *podRoute)
		res.IPs = append(res.IPs, ipConfig)
		res.Routes = append(res.Routes, routes...)
		res.Routes = append(res.Routes, newCNIRoute(podRoute))
	}

	if hasIPv4 {
		ep.Addressing.IPV4 = podIPv4.String()

		mtu := int(conf.RouteMTU)
		ipConfig, routes, err = prepareIP(ep.Addressing.IPV4, &state, mtu)
		if err != nil {
			return nil, fmt.Errorf("unable to prepare IPv4 addressing for %q: %s", ep.Addressing.IPV4, err)
		}

		m := conf.DaemonConfigurationMap["IPv4NativeRoutingCIDR"].(string)
		dst := cidr.MustParseCIDR(m)
		dst.IP.To4()[1] += byte(sort.SearchStrings(networks, networkName) + 1)

		r := &route.Route{
			Prefix: *dst.IPNet,
			Device: attachIfaceName,
		}
		podRoute := r

		// TODO: address & netmask (?) should come from IPAM. Might also want a separate MTU.
		//podRoute := getMultiHomingPodRoute(podIPv4, mtu)
		state.IP4routes = append(state.IP4routes, *podRoute)
		res.IPs = append(res.IPs, ipConfig)
		res.Routes = append(res.Routes, routes...)
		res.Routes = append(res.Routes, newCNIRoute(podRoute))
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
