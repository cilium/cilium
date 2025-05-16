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
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/client"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/netns"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	"github.com/cilium/cilium/plugins/cilium-cni/lib"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
)

type GenericVethChainer struct{}

func (f *GenericVethChainer) Add(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *client.Client) (res *cniTypesVer.Result, err error) {
	err = cniVersion.ParsePrevResult(&pluginCtx.NetConf.NetConf)
	if err != nil {
		err = fmt.Errorf("unable to understand network config: %w", err)
		return
	}

	var prevRes *cniTypesVer.Result
	prevRes, err = cniTypesVer.NewResultFromResult(pluginCtx.NetConf.PrevResult)
	if err != nil {
		err = fmt.Errorf("unable to get previous network result: %w", err)
		return
	}

	defer func() {
		if err != nil {
			pluginCtx.Logger.Error(
				"Unable to create endpoint",
				logfields.Error, err,
				logfields.Previous, pluginCtx.NetConf.PrevResult,
			)
		}
	}()
	var (
		hostMac, vethHostName, vethLXCMac, vethLXCName, vethIP, vethIPv6 string
		vethHostIdx, peerIndex                                           int
		peer                                                             netlink.Link
	)

	ns, err := netns.OpenPinned(pluginCtx.Args.Netns)
	if err != nil {
		return nil, fmt.Errorf("failed to open netns %q: %w", pluginCtx.Args.Netns, err)
	}
	defer ns.Close()

	if err = ns.Do(func() error {
		links, err := safenetlink.LinkList()
		if err != nil {
			return err
		}

		linkFound := false
		for _, link := range links {
			pluginCtx.Logger.Debug(
				"Found interface in container",
				logfields.Interface, link.Attrs(),
			)

			if link.Type() != "veth" {
				continue
			}

			vethLXCMac = link.Attrs().HardwareAddr.String()
			vethLXCName = link.Attrs().Name

			veth, ok := link.(*netlink.Veth)
			if !ok {
				return fmt.Errorf("link %s is not a veth interface", vethHostName)
			}

			peerIndex, err = netlink.VethPeerIndex(veth)
			if err != nil {
				return fmt.Errorf("unable to retrieve index of veth peer %s: %w", vethHostName, err)
			}

			addrs, err := safenetlink.AddrList(link, netlink.FAMILY_V4)
			if err == nil && len(addrs) > 0 {
				vethIP = addrs[0].IPNet.IP.String()
			} else if err != nil {
				pluginCtx.Logger.Warn(
					"No valid IPv4 address found",
					logfields.Error, err,
					logfields.Interface, link.Attrs().Name,
				)
			}

			addrsv6, err := safenetlink.AddrList(link, netlink.FAMILY_V6)
			if err == nil && len(addrsv6) > 0 {
				if len(addrsv6) == 1 {
					vethIPv6 = addrsv6[0].IPNet.IP.String()
				} else {
					for _, addrv6 := range addrsv6 {
						if addrv6.IP.IsGlobalUnicast() {
							vethIPv6 = addrv6.IPNet.IP.String()
							break
						}
					}
				}
			} else if err != nil {
				pluginCtx.Logger.Warn(
					"No valid IPv6 address found",
					logfields.Error, err,
					logfields.Interface, link.Attrs().Name,
				)
			}

			linkFound = true
			break
		}

		if !linkFound {
			return errors.New("no link found inside container")
		}

		if pluginCtx.NetConf.EnableRouteMTU || pluginCtx.CiliumConf.EnableRouteMTUForCNIChaining {
			routes, err := safenetlink.RouteList(nil, netlink.FAMILY_V4)
			if err != nil {
				err = fmt.Errorf("unable to list the IPv4 routes: %w", err)
				return err
			}
			for _, rt := range routes {
				if rt.MTU != int(pluginCtx.CiliumConf.RouteMTU) {
					rt.MTU = int(pluginCtx.CiliumConf.RouteMTU)
					err = netlink.RouteReplace(&rt)
					if err != nil {
						err = fmt.Errorf("unable to replace the mtu %d for the route %s: %s", rt.MTU, rt.String(), err.Error())
						return err
					}
				}
			}

			routes, err = safenetlink.RouteList(nil, netlink.FAMILY_V6)
			if err != nil {
				err = fmt.Errorf("unable to list the IPv6 routes: %w", err)
				return err
			}
			for _, rt := range routes {
				if rt.MTU != int(pluginCtx.CiliumConf.RouteMTU) {
					rt.MTU = int(pluginCtx.CiliumConf.RouteMTU)
					err = netlink.RouteReplace(&rt)
					if err != nil {
						err = fmt.Errorf("unable to replace the mtu %d for the route %s: %s", rt.MTU, rt.String(), err.Error())
						return err
					}
				}
			}
		}

		return nil
	}); err != nil {
		return
	}

	peer, err = netlink.LinkByIndex(peerIndex)
	if err != nil {
		err = fmt.Errorf("unable to lookup link %d: %w", peerIndex, err)
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
		ContainerID:            pluginCtx.Args.ContainerID,
		State:                  models.EndpointStateWaitingDashForDashIdentity.Pointer(),
		HostMac:                hostMac,
		InterfaceIndex:         int64(vethHostIdx),
		Mac:                    vethLXCMac,
		InterfaceName:          vethHostName,
		ContainerInterfaceName: vethLXCName,
		K8sPodName:             string(pluginCtx.CniArgs.K8S_POD_NAME),
		K8sNamespace:           string(pluginCtx.CniArgs.K8S_POD_NAMESPACE),
		K8sUID:                 string(pluginCtx.CniArgs.K8S_POD_UID),
		SyncBuildEndpoint:      true,
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

	scopedLogger := pluginCtx.Logger.With(
		logfields.ContainerID, ep.ContainerID,
		logfields.ContainerInterface, ep.ContainerInterfaceName,
	)
	var newEp *models.Endpoint
	newEp, err = cli.EndpointCreate(ep)
	if err != nil {
		scopedLogger.Warn("Unable to create endpoint", logfields.Error, err)
		err = fmt.Errorf("unable to create endpoint: %w", err)
		return
	}
	if newEp != nil && newEp.Status != nil && newEp.Status.Networking != nil && newEp.Status.Networking.Mac != "" &&
		newEp.Status.Networking.Mac != vethLXCMac {

		err = ns.Do(func() error {
			return mac.ReplaceMacAddressWithLinkName(vethLXCName, newEp.Status.Networking.Mac)
		})
		if err != nil {
			err = fmt.Errorf("unable to set MAC address on interface %s: %w", vethLXCName, err)
			return
		}
		for i := range prevRes.Interfaces {
			if prevRes.Interfaces[i].Name == vethLXCName {
				prevRes.Interfaces[i].Mac = newEp.Status.Networking.Mac
			}
		}
	}
	scopedLogger.Debug("Endpoint successfully created")

	res = prevRes

	return
}

func (f *GenericVethChainer) Delete(ctx context.Context, pluginCtx chainingapi.PluginContext, delClient *lib.DeletionFallbackClient) (err error) {
	req := &models.EndpointBatchDeleteRequest{ContainerID: pluginCtx.Args.ContainerID}
	if err := delClient.EndpointDeleteMany(req); err != nil {
		pluginCtx.Logger.Warn(
			"Errors encountered while deleting endpoint",
			logfields.Error, err,
		)
	}
	return nil
}

func (f *GenericVethChainer) Check(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *client.Client) error {
	// Just confirm that the endpoint is healthy
	eID := endpointid.NewCNIAttachmentID(pluginCtx.Args.ContainerID, pluginCtx.Args.IfName)
	pluginCtx.Logger.Warn(
		"Asking agent for healthz for endpoint",
		logfields.EndpointID, eID,
	)
	epHealth, err := cli.EndpointHealthGet(eID)
	if err != nil {
		return cniTypes.NewError(types.CniErrHealthzGet, "HealthzFailed",
			fmt.Sprintf("failed to retrieve container health: %s", err))
	}

	if epHealth.OverallHealth == models.EndpointHealthStatusFailure {
		return cniTypes.NewError(types.CniErrUnhealthy, "Unhealthy",
			"container is unhealthy in agent")
	}
	pluginCtx.Logger.Debug(
		"Container has a healthy agent endpoint",
		logfields.ContainerID, pluginCtx.Args.ContainerID,
		logfields.Interface, pluginCtx.Args.IfName,
	)
	return nil
}

func (f *GenericVethChainer) Status(ctx context.Context, pluginCtx chainingapi.PluginContext, cli *client.Client) error {
	if _, err := cli.Daemon.GetHealthz(nil); err != nil {
		return cniTypes.NewError(types.CniErrPluginNotAvailable, "DaemonHealthzFailed",
			fmt.Sprintf("Cilium agent healthz check failed: %s", client.Hint(err)))
	}
	return nil
}

func init() {
	chainingapi.Register("generic-veth", &GenericVethChainer{})
}
