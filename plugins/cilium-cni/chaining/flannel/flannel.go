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

package flannel

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/logging/logfields"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"

	cniTypesVer "github.com/containernetworking/cni/pkg/types/current"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

type flannelChainer struct{}

func (f *flannelChainer) ImplementsAdd() bool {
	return true
}

func (f *flannelChainer) Add(ctx context.Context, pluginCtx chainingapi.PluginContext) (res *cniTypesVer.Result, err error) {
	err = cniVersion.ParsePrevResult(&pluginCtx.NetConf.NetConf)
	if err != nil {
		return nil, fmt.Errorf("unable to understand network config: %s", err)
	}
	r, err := cniTypesVer.GetResult(pluginCtx.NetConf.PrevResult)
	if err != nil {
		return nil, fmt.Errorf("unable to get previous network result: %s", err)
	}
	// We only care about the veth interface that is on the host side
	// and cni0. Interfaces should be similar as:
	//       "interfaces":[
	//         {
	//            "name":"cni0",
	//            "mac":"0a:58:0a:f4:00:01"
	//         },
	//         {
	//            "name":"veth15707e9b",
	//            "mac":"4e:6d:93:35:6b:45"
	//         },
	//         {
	//            "name":"eth0",
	//            "mac":"0a:58:0a:f4:00:06",
	//            "sandbox":"/proc/15259/ns/net"
	//         }
	//       ]

	defer func() {
		if err != nil {
			pluginCtx.Logger.WithError(err).
				WithFields(logrus.Fields{"cni-pre-result": pluginCtx.NetConf.PrevResult.String()}).
				Errorf("Unable to create endpoint")
		}
	}()
	var (
		hostMac, vethHostName, vethLXCMac, vethIP string
		vethHostIdx, vethSliceIdx                 int
	)
	for i, iDev := range r.Interfaces {
		// We only care about the veth interface mac address on the container side.
		if iDev.Sandbox != "" {
			vethLXCMac = iDev.Mac
			vethSliceIdx = i
			continue
		}

		l, err := netlink.LinkByName(iDev.Name)
		if err != nil {
			continue
		}
		switch l.Type() {
		case "veth":
			vethHostName = iDev.Name
			vethHostIdx = l.Attrs().Index
		case "bridge":
			// likely to be cni0
			hostMac = iDev.Mac
		}
	}
	for _, ipCfg := range r.IPs {
		if ipCfg.Interface != nil && *ipCfg.Interface == vethSliceIdx {
			vethIP = ipCfg.Address.IP.String()
			break
		}
	}
	switch {
	case hostMac == "":
		return nil, errors.New("unable to determine MAC address of bridge interface (cni0)")
	case vethHostName == "":
		return nil, errors.New("unable to determine name of veth pair on the host side")
	case vethLXCMac == "":
		return nil, errors.New("unable to determine MAC address of veth pair on the container side")
	case vethIP == "":
		return nil, errors.New("unable to determine IP address of the container")
	case vethHostIdx == 0:
		return nil, errors.New("unable to determine index interface of veth pair on the host side")
	}

	ep := &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPV4: vethIP,
		},
		ContainerID:       pluginCtx.Args.ContainerID,
		State:             models.EndpointStateWaitingForIdentity,
		HostMac:           hostMac,
		InterfaceIndex:    int64(vethHostIdx),
		Mac:               vethLXCMac,
		InterfaceName:     vethHostName,
		K8sPodName:        string(pluginCtx.CniArgs.K8S_POD_NAME),
		K8sNamespace:      string(pluginCtx.CniArgs.K8S_POD_NAMESPACE),
		SyncBuildEndpoint: true,
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
	return &cniTypesVer.Result{}, nil
}

func (f *flannelChainer) ImplementsDelete() bool {
	return false
}

func (f *flannelChainer) Delete(ctx context.Context, pluginCtx chainingapi.PluginContext) (err error) {
	return nil
}

func init() {
	chainingapi.Register("cbr0", &flannelChainer{})
}
