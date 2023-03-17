// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package podlink

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/pkg/datapath/connector"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/ebpf"
	cniTypes "github.com/containernetworking/cni/pkg/types"
	cniTypesVer "github.com/containernetworking/cni/pkg/types/100"
	cniVersion "github.com/containernetworking/cni/pkg/version"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/models"
	endpointid "github.com/cilium/cilium/pkg/endpoint/id"
	"github.com/cilium/cilium/pkg/logging/logfields"
	chainingapi "github.com/cilium/cilium/plugins/cilium-cni/chaining/api"
	"github.com/cilium/cilium/plugins/cilium-cni/types"
	"github.com/containernetworking/plugins/pkg/ns"
)

type PodlinkChainer struct{}

func (f *PodlinkChainer) ImplementsAdd() bool {
	return true
}

func (f *PodlinkChainer) Add(ctx context.Context, pluginCtx chainingapi.PluginContext) (res *cniTypesVer.Result, err error) {
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

	sms := connector.StubMapSpec{
		MaxEntries: 2,
		Progs: []connector.EntryProgSpec{
			{
				Index:    loader.DirectionToEntryIndex(loader.DirIngress),
				ProgName: connector.PodlinkEntryFromEndpoint,
				Attach: func(link netlink.Link, prog *ebpf.Program, progName string) error {
					return loader.AttachProgram(link, prog, progName, loader.ATTA_F_TC_INGRESS)
				},
			},
			{
				Index:    loader.DirectionToEntryIndex(loader.DirEgress),
				ProgName: connector.PodlinkEntryToEndpoint,
				Attach: func(link netlink.Link, prog *ebpf.Program, progName string) error {
					return loader.AttachProgram(link, prog, progName, loader.ATTA_F_TC_EGRESS)
				},
			},
		},
	}

	m, info, err := connector.SetupPodlink(netNs, sms)
	if err != nil {
		err = fmt.Errorf("unable to setup podlink in container %q: %s", pluginCtx.Args.Netns, err)
		return
	}
	if info.IPv4 == "" && info.IPv6 == "" {
		err = fmt.Errorf("unable to determine IP address of the container %q", pluginCtx.Args.Netns)
		return
	}

	defer m.Close()
	mapInfo, err := m.Info()
	if err != nil {
		err = fmt.Errorf("failed to get map info: %w", err)
		return
	}
	mapID, valid := mapInfo.ID()
	if !valid {
		err = fmt.Errorf("failed to get map id")
		return
	}

	// create endpoint
	var disabled = false
	ep := &models.EndpointChangeRequest{
		Addressing: &models.AddressPair{
			IPV4: info.IPv4,
			IPV6: info.IPv6,
		},
		ContainerID:       pluginCtx.Args.ContainerID,
		State:             models.EndpointStateWaitingDashForDashIdentity.Pointer(),
		HostMac:           info.Mac,
		InterfaceIndex:    int64(info.Index),
		Mac:               info.Mac,
		InterfaceName:     info.Name,
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

func (f *PodlinkChainer) ImplementsDelete() bool {
	return true
}

func (f *PodlinkChainer) Delete(ctx context.Context, pluginCtx chainingapi.PluginContext) (err error) {
	id := endpointid.NewID(endpointid.ContainerIdPrefix, pluginCtx.Args.ContainerID)
	if err := pluginCtx.Client.EndpointDelete(id); err != nil {
		pluginCtx.Logger.WithError(err).Warning("Errors encountered while deleting endpoint")
	}
	return nil
}

func (f *PodlinkChainer) Check(ctx context.Context, pluginCtx chainingapi.PluginContext) error {
	// Just confirm that the endpoint is healthy
	eID := fmt.Sprintf("container-id:%s", pluginCtx.Args.ContainerID)
	pluginCtx.Logger.Debugf("Asking agent for healthz for %s", eID)
	epHealth, err := pluginCtx.Client.EndpointHealthGet(eID)
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
	chainingapi.Register("podlink", &PodlinkChainer{})
}
