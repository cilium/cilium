// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package genericveth

import (
	"context"
	"errors"
	"fmt"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/logging/logfields"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	"github.com/cilium/cilium/plugins/cilium-cni/lib"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

type GenericVethChainer struct{}

func (f *GenericVethChainer) Add(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *client.Client) (res *cniTypesVer.Result, err error) {
	err = cniVersion.ParsePrevResult(&pluginCtx.NetConf.NetConf)
	if err != nil {
		err = fmt.Errorf("unable to understand network config: %s", err)
		return
	}

	var prevRes *cniTypesVer.Result
	prevRes, err = cniTypesVer.NewResultFromResult(pluginCtx.NetConf.PrevResult)
	if err != nil {
		err = fmt.Errorf("unable to get previous network result: %s", err)
		return
	}

	defer func() {
		if err != nil {
			pluginCtx.Logger.WithError(err).
				WithFields(logrus.Fields{"cni-pre-result": pluginCtx.NetConf.PrevResult}).
				Errorf("Unable to create endpoint")
		}
	}()
	var (
		hostMac, vethHostName, vethLXCMac, vethIP, vethIPv6 string
		vethHostIdx, peerIndex                              int
		peer                                                netlink.Link
		netNs                                               ns.NetNS
	)

	netNs, err = ns.GetNS(pluginCtx.Args.Netns)
	if err != nil {
		err = fmt.Errorf("failed to open netns %q: %s", pluginCtx.Args.Netns, err)
		return
	}
	defer netNs.Close()

	if err = netNs.Do(func(_ ns.NetNS) error {
		links, err := netlink.LinkList()
		if err != nil {
			return err
		}

		for _, link := range links {
			pluginCtx.Logger.Debugf("Found interface in container %+v", link.Attrs())

			if link.Type() != "veth" {
				continue
			}

			vethLXCMac = link.Attrs().HardwareAddr.String()

			veth, ok := link.(*netlink.Veth)
			if !ok {
				return fmt.Errorf("link %s is not a veth interface", vethHostName)
			}

			peerIndex, err = netlink.VethPeerIndex(veth)
			if err != nil {
				return fmt.Errorf("unable to retrieve index of veth peer %s: %s", vethHostName, err)
			}

			addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
			if err == nil && len(addrs) > 0 {
				vethIP = addrs[0].IPNet.IP.String()
			} else if err != nil {
				pluginCtx.Logger.WithError(err).WithFields(logrus.Fields{
					logfields.Interface: link.Attrs().Name}).Warn("No valid IPv4 address found")
			}

			addrsv6, err := netlink.AddrList(link, netlink.FAMILY_V6)
			if err == nil && len(addrsv6) > 0 {
				vethIPv6 = addrsv6[0].IPNet.IP.String()
			} else if err != nil {
				pluginCtx.Logger.WithError(err).WithFields(logrus.Fields{
					logfields.Interface: link.Attrs().Name}).Warn("No valid IPv6 address found")
			}

			return nil
		}

		return fmt.Errorf("no link found inside container")
	}); err != nil {
		return
	}

	peer, err = netlink.LinkByIndex(peerIndex)
	if err != nil {
		err = fmt.Errorf("unable to lookup link %d: %s", peerIndex, err)
		return
	}

	hostMac = peer.Attrs().HardwareAddr.String()
	vethHostName = peer.Attrs().Name
	vethHostIdx = peer.Attrs().Index

	switch {
	case vethHostName == "":
		err = errors.New("unable to determine name of veth pair on the host side")
		return
	case vethLXCMac == "":
		err = errors.New("unable to determine MAC address of veth pair on the container side")
		return
	case vethIP == "" && vethIPv6 == "":
		err = errors.New("unable to determine IP address of the container")
		return
	case vethHostIdx == 0:
		err = errors.New("unable to determine index interface of veth pair on the host side")
		return
	}

	var disabled = false
	ep := &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPV4: vethIP,
			IPV6: vethIPv6,
		},
		ContainerID:       pluginCtx.Args.ContainerID,
		State:             models.EndpointStateWaitingDashForDashIdentity.Pointer(),
		HostMac:           hostMac,
		InterfaceIndex:    int64(vethHostIdx),
		Mac:               vethLXCMac,
		InterfaceName:     vethHostName,
		K8sPodName:        string(pluginCtx.CniArgs.K8S_POD_NAME),
		K8sNamespace:      string(pluginCtx.CniArgs.K8S_POD_NAMESPACE),
		SyncBuildEndpoint: true,
		DatapathConfiguration: &models.EndpointDatapathConfiguration{
			// aws-cni requires ARP passthrough between Linux and
			// the pod
			RequireArpPassthrough: true,

			// The route is pointing directly into the veth of the
			// pod, install a host-facing egress program to
			// implement ingress policy and to provide reverse NAT
			RequireEgressProg: true,

			// The IP is managed by the aws-cni plugin, no need for
			// Cilium to manage any aspect of addressing
			ExternalIpam: true,

			// All routing is performed by the Linux stack
			RequireRouting: &disabled,
		},
	}

	err = cli.EndpointCreate(ep)
	if err != nil {
		pluginCtx.Logger.WithError(err).WithFields(logrus.Fields{
			logfields.ContainerID: ep.ContainerID}).Warn("Unable to create endpoint")
		err = fmt.Errorf("unable to create endpoint: %s", err)
		return
	}

	pluginCtx.Logger.WithFields(logrus.Fields{
		logfields.ContainerID: ep.ContainerID}).Debug("Endpoint successfully created")

	res = prevRes

	return
}

func (f *GenericVethChainer) Delete(ctx context.Context, pluginCtx chainingapi.PluginContext, delClient *lib.DeletionFallbackClient) (err error) {
	id := endpointid.NewID(endpointid.ContainerIdPrefix, pluginCtx.Args.ContainerID)
	if err := delClient.EndpointDelete(id); err != nil {
		pluginCtx.Logger.WithError(err).Warning("Errors encountered while deleting endpoint")
	}
	return nil
}

func (f *GenericVethChainer) Check(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *client.Client) error {
	// Just confirm that the endpoint is healthy
	eID := fmt.Sprintf("container-id:%s", pluginCtx.Args.ContainerID)
	pluginCtx.Logger.Debugf("Asking agent for healthz for %s", eID)
	epHealth, err := cli.EndpointHealthGet(eID)
	if err != nil {
		return cniTypes.NewError(types.CniErrHealthzGet, "HealthzFailed",
			fmt.Sprintf("failed to retrieve container health: %s", err))
	}

	if epHealth.OverallHealth == models.EndpointHealthStatusFailure {
		return cniTypes.NewError(types.CniErrUnhealthy, "Unhealthy",
			"container is unhealthy in agent")
	}
	pluginCtx.Logger.Debugf("Container %s has a healthy agent endpoint", pluginCtx.Args.ContainerID)
	return nil
}

func init() {
	chainingapi.Register("generic-veth", &GenericVethChainer{})
}
