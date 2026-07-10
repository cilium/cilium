// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package instance

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/bgp/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// BGPInstance is a container for providing interface with underlying router implementation.
type BGPInstance struct {
	Name                string
	Global              types.BGPGlobal
	CancelCtx           context.CancelFunc
	Config              *v2.CiliumBGPNodeInstance
	Router              types.Router
	stateNotificationCh chan struct{}
}

func (i *BGPInstance) NotifyStateChange() {
	select {
	case i.stateNotificationCh <- struct{}{}:
	default:
	}
}

// NewBGPInstance will start an underlying BGP instance using the provided types.RouterProvider,
// utilizing types.ServerParameters for its initial configuration.
//
// The returned BGPInstance has a nil CiliumBGPNodeInstance config, and is
// ready to be provided to ReconcileBGPConfig.
//
// Canceling the provided context will kill the BGP instance along with calling the
// underlying Router's Stop() method.
func NewBGPInstance(ctx context.Context, routerProvider types.RouterProvider, log *slog.Logger, name string, params types.ServerParameters) (*BGPInstance, error) {
	routerCtx, cancel := context.WithCancel(ctx)
	s, err := routerProvider.NewRouter(routerCtx, log, params)
	if err != nil {
		cancel()
		return nil, err
	}

	return &BGPInstance{
		Name:                name,
		Global:              params.Global,
		CancelCtx:           cancel,
		Config:              nil,
		Router:              s,
		stateNotificationCh: params.StateNotification,
	}, nil
}
