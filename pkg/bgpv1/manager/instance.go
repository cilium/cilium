// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"

	"github.com/cilium/cilium/pkg/bgpv1/gobgp"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
)

// ServerWithConfig is a container for providing interface with underlying router implementation
// and Cilium's BGP control plane related configuration.
//
// It exports a method set for manipulating the BgpServer. However, this
// struct is a dumb object. The calling code is required to keep the BgpServer's
// configuration and associated configuration fields in sync.
type ServerWithConfig struct {
	// backed BgpServer configured in accordance to the accompanying
	// CiliumBGPVirtualRouter configuration.
	Server types.Router

	// The CiliumBGPVirtualRouter configuration which drives the configuration
	// of the above BgpServer.
	//
	// If this field is nil it means the above BgpServer has had no
	// configuration applied to it.
	Config *v2alpha1api.CiliumBGPVirtualRouter

	// Holds any announced PodCIDR routes.
	PodCIDRAnnouncements []types.Advertisement

	// Holds any announced Service routes.
	ServiceAnnouncements map[resource.Key][]types.Advertisement
}

// NewServerWithConfig will start an underlying BgpServer utilizing types.ServerParameters
// for its initial configuration.
//
// The returned ServerWithConfig has a nil CiliumBGPVirtualRouter config, and is
// ready to be provided to ReconcileBGPConfig.
//
// Canceling the provided context will kill the BgpServer along with calling the
// underlying BgpServer's Stop() method.
func NewServerWithConfig(ctx context.Context, params types.ServerParameters) (*ServerWithConfig, error) {
	s, err := gobgp.NewGoBGPServerWithConfig(ctx, log, params)
	if err != nil {
		return nil, err
	}

	return &ServerWithConfig{
		Server:               s,
		Config:               nil,
		PodCIDRAnnouncements: []types.Advertisement{},
		ServiceAnnouncements: make(map[resource.Key][]types.Advertisement),
	}, nil
}
