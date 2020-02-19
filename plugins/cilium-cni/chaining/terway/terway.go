// Copyright 2019 Authors of Cilium
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

package terway

import (
	"context"
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/datapath/connector"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	cniTypesVer "github.com/containernetworking/cni/pkg/types/current"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

var (
	name             = "terway-chainer"
	log              = logging.DefaultLogger.WithField(logfields.LogSubsys, name)
	vpcNetGatewayMac = "ee:ff:ff:ff:ff:ff"
)

// TerwayChainer is terway chain object
type TerwayChainer struct{}

// ImplementsAdd returns true if method 'add' is available
func (f *TerwayChainer) ImplementsAdd() bool {
	return true
}

// Add setups the ipvlan port's tc-bpf
func (f *TerwayChainer) Add(ctx context.Context, pluginCtx chainingapi.PluginContext) (res *cniTypesVer.Result, err error) {
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
				WithFields(logrus.Fields{"cni-pre-result": pluginCtx.NetConf.PrevResult.String()}).
				Errorf("Unable to create endpoint")
		}
	}()

	netNs, err := ns.GetNS(pluginCtx.Args.Netns)
	if err != nil {
		err = fmt.Errorf("failed to open netns %q: %s", pluginCtx.Args.Netns, err)
		return
	}
	defer netNs.Close()

	var (
		ifName                    = ""
		disabled                  = false
		containerIP, containerMac string
		containerIfIndex          int
		hostMac                   = vpcNetGatewayMac
	)

	if err = netNs.Do(func(_ ns.NetNS) error {
		links, err := netlink.LinkList()
		if err != nil {
			return fmt.Errorf("failed to list link %s", pluginCtx.Args.Netns)
		}
		for _, link := range links {
			if link.Type() != "ipvlan" {
				continue
			}

			ifName = link.Attrs().Name
			containerMac = link.Attrs().HardwareAddr.String()

			addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
			if err != nil {
				return fmt.Errorf("unable to list addresses for link %s: %s", link.Attrs().Name, err)
			}
			if len(addrs) < 1 {
				return fmt.Errorf("no address configured inside container")
			}

			containerIP = addrs[0].IPNet.IP.String()
			return nil
		}

		return fmt.Errorf("no link found inside container")
	}); err != nil {
		return
	}

	var (
		mapFD, mapID int
	)

	// set bpf
	mapFD, mapID, err = connector.SetupIpvlanInRemoteNsWithBPF(netNs, ifName, ifName, true, true)
	if err != nil {
		pluginCtx.Logger.WithError(err).Warn("Unable to set ipvlan ebpf")
		return
	}
	defer unix.Close(mapFD)

	// create endpoint
	ep := &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPV4: containerIP,
		},
		ContainerID:       pluginCtx.Args.ContainerID,
		State:             models.EndpointStateWaitingForIdentity,
		HostMac:           hostMac,
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

// ImplementsDelete return true if method 'delete' is available
func (f *TerwayChainer) ImplementsDelete() bool {
	return true
}

// Delete deletes cilium endpoint
func (f *TerwayChainer) Delete(ctx context.Context, pluginCtx chainingapi.PluginContext) (err error) {
	id := endpointid.NewID(endpointid.ContainerIdPrefix, pluginCtx.Args.ContainerID)
	if err := pluginCtx.Client.EndpointDelete(id); err != nil {
		log.WithError(err).Warning("Errors encountered while deleting endpoint")
	}
	return nil
}

func init() {
	chainingapi.Register(name, &TerwayChainer{})
}
