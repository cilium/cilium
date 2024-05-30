// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package speaker

import (
	"context"

	"github.com/cilium/hive/cell"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides access to the MetalLB BGP Speaker.
var Cell = cell.Module(
	"metallb-bgp",
	"MetalLB BGP",

	cell.Provide(newMetalLBBGPSpeaker),
)

type speakerParams struct {
	cell.In

	Lifecycle cell.Lifecycle

	Clientset       k8sClient.Clientset
	SvcCache        *k8s.ServiceCache
	LocalNode       daemonk8s.LocalNodeResource
	LocalCiliumNode daemonk8s.LocalCiliumNodeResource
}

func newMetalLBBGPSpeaker(params speakerParams) (MetalLBBgpSpeaker, error) {
	if !option.Config.BGPAnnounceLBIP && !option.Config.BGPAnnouncePodCIDR {
		return &noopSpeaker{}, nil
	}

	log.
		WithField("url", "https://github.com/cilium/cilium/issues/22246").
		Warn("You are using the legacy BGP feature, which will only receive security updates and bugfixes. " +
			"It is recommended to migrate to the BGP Control Plane feature if possible, which has better support.")

	speaker, err := newSpeaker(params.Clientset, params.SvcCache, Opts{
		LoadBalancerIP: option.Config.BGPAnnounceLBIP,
		PodCIDR:        option.Config.BGPAnnouncePodCIDR,
	})
	if err != nil {
		return nil, err
	}

	ctx, cf := context.WithCancel(context.Background())

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(_ cell.HookContext) error {
			go speaker.run(ctx)
			log.Info("Started BGP speaker")

			switch option.Config.IPAMMode() {
			case ipamOption.IPAMKubernetes:
				speaker.subscribeToLocalNodeResource(ctx, params.LocalNode)
			case ipamOption.IPAMClusterPool:
				speaker.subscribeToLocalCiliumNodeResource(ctx, params.LocalCiliumNode)
			}
			return nil
		},
		OnStop: func(_ cell.HookContext) error {
			cf()
			return nil
		},
	})

	return speaker, nil
}
