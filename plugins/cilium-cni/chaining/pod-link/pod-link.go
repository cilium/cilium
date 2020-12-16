// Copyright 2020 Authors of Cilium
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

package podlink

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/connector"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/logging/logfields"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"

	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

const name = "pod-link"

type GenericLink struct{}

// ImplementsAdd returns true if method 'add' is available
func (g *GenericLink) ImplementsAdd() bool {
	return true
}

// Add setups the link port's tc-bpf
func (g *GenericLink) Add(ctx context.Context, pluginCtx chainingapi.PluginContext) (res *cniTypesVer.Result, err error) {
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
			pluginCtx.Logger.WithError(err).
				WithFields(logrus.Fields{"cni-pre-result": pluginCtx.NetConf.PrevResult}).
				Errorf("Unable to create endpoint")
		}
	}()

	netNs, err := ns.GetNS(pluginCtx.Args.Netns)
	if err != nil {
		err = fmt.Errorf("failed to open netns %q: %w", pluginCtx.Args.Netns, err)
		return
	}
	defer netNs.Close()

	var (
		ifName                                     = ""
		disabled                                   = false
		containerIPv4, containerIPv6, containerMac string
		containerIfIndex                           int
	)

	if err = netNs.Do(func(_ ns.NetNS) error {
		links, err := netlink.LinkList()
		if err != nil {
			return fmt.Errorf("failed to list link %s", pluginCtx.Args.Netns)
		}
		for _, link := range links {
			pluginCtx.Logger.Debugf("Found interface in container %+v", link.Attrs())

			if link.Attrs().Name == "lo" {
				continue
			}

			ifName = link.Attrs().Name
			containerMac = link.Attrs().HardwareAddr.String()

			addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
			if err == nil && len(addrs) > 0 {
				containerIPv4 = addrs[0].IPNet.IP.String()
			} else if err != nil {
				pluginCtx.Logger.WithError(err).WithFields(logrus.Fields{
					logfields.Interface: link.Attrs().Name}).Warn("No valid IPv4 address found")
			}

			addrsv6, err := netlink.AddrList(link, netlink.FAMILY_V6)
			if err == nil && len(addrsv6) > 0 {
				containerIPv6 = addrsv6[0].IPNet.IP.String()
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

	if containerIPv4 == "" && containerIPv6 == "" {
		err = errors.New("unable to determine IP address of the container")
		return
	}

	// set bpf
	m, err := connector.SetupNicInRemoteNs(netNs, ifName, ifName, true, true)
	if err != nil {
		pluginCtx.Logger.WithError(err).Warn("Unable to set ebpf")
		return
	}
	defer m.Close()
	mapID, err := m.ID()
	if err != nil {
		return nil, fmt.Errorf("failed to get map ID: %w", err)
	}

	// create endpoint
	ep := &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPV4: containerIPv4,
			IPV6: containerIPv6,
		},
		ContainerID:       pluginCtx.Args.ContainerID,
		State:             models.EndpointStateWaitingForIdentity,
		HostMac:           containerMac,
		InterfaceIndex:    int64(containerIfIndex),
		Mac:               containerMac,
		InterfaceName:     ifName,
		K8sPodName:        string(pluginCtx.CniArgs.K8S_POD_NAME),
		K8sNamespace:      string(pluginCtx.CniArgs.K8S_POD_NAMESPACE),
		SyncBuildEndpoint: true,
		DatapathMapID:     int64(mapID),
		DatapathConfiguration: &models.EndpointDatapathConfiguration{
			RequireArpPassthrough: true,
			RequireEgressProg:     true,
			ExternalIpam:          true,
			RequireRouting:        &disabled,
		},
	}

	err = pluginCtx.Client.EndpointCreate(ep)
	if err != nil {
		pluginCtx.Logger.WithError(err).WithField(logfields.ContainerID, ep.ContainerID).Warn("Unable to create endpoint")
		err = fmt.Errorf("unable to create endpoint: %s", err)
		return
	}

	pluginCtx.Logger.WithField(logfields.ContainerID, ep.ContainerID).Debug("Endpoint successfully created")

	res = prevRes
	return
}

// ImplementsDelete return true if method 'delete' is available
func (g *GenericLink) ImplementsDelete() bool {
	return true
}

// Delete deletes cilium endpoint
func (g *GenericLink) Delete(ctx context.Context, pluginCtx chainingapi.PluginContext) (err error) {
	id := endpointid.NewID(endpointid.ContainerIdPrefix, pluginCtx.Args.ContainerID)
	if err := pluginCtx.Client.EndpointDelete(id); err != nil {
		pluginCtx.Logger.WithError(err).Warning("Errors encountered while deleting endpoint")
	}
	return nil
}

func init() {
	chainingapi.Register(name, &GenericLink{})
}
