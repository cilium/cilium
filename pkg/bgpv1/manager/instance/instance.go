// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package instance

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/bgpv1/gobgp"
	"github.com/cilium/cilium/pkg/bgpv1/types"
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

// NewBGPInstance will start an underlying BGP instance utilizing types.ServerParameters
// for its initial configuration.
//
// The returned BGPInstance has a nil CiliumBGPNodeInstance config, and is
// ready to be provided to ReconcileBGPConfig.
//
// Canceling the provided context will kill the BGP instance along with calling the
// underlying Router's Stop() method.
func NewBGPInstance(ctx context.Context, log *slog.Logger, name string, params types.ServerParameters) (*BGPInstance, error) {
	gobgpCtx, cancel := context.WithCancel(ctx)
	s, err := gobgp.NewGoBGPServer(gobgpCtx, log, params)
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
