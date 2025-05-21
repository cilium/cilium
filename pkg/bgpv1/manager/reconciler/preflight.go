// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type PreflightReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

// PreflightReconciler is a preflight task before any other reconciliation should
// take place.
//
// this reconciler handles any changes in current and desired BgpState which leads
// to a recreation of an existing BgpServer.
//
// this must be done first so that the following reconciliation functions act
// upon the recreated BgpServer with the desired permanent configurations.
//
// permanent configurations for BgpServers (ones that cannot be changed after creation)
// are router ID and local listening port.
type PreflightReconciler struct {
	logger *slog.Logger
}

func NewPreflightReconciler(logger *slog.Logger) PreflightReconcilerOut {
	return PreflightReconcilerOut{
		Reconciler: &PreflightReconciler{
			logger: logger.With(types.ComponentLogField, "PreflightReconciler"),
		},
	}
}

func (r *PreflightReconciler) Name() string {
	return "Preflight"
}

func (r *PreflightReconciler) Priority() int {
	return 10
}

func (r *PreflightReconciler) Init(_ *instance.ServerWithConfig) error {
	return nil
}

func (r *PreflightReconciler) Cleanup(_ *instance.ServerWithConfig) {}

func (r *PreflightReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	var (
		l = r.logger.With(
			types.LocalASNLogField, p.DesiredConfig.LocalASN,
		)
	)

	// If we have no config attached, we don't need to perform a preflight for
	// reconciliation.
	//
	// This is the first time this server is being registered and BGPRouterManager
	// set any fields needing reconciliation in this function already.
	if p.CurrentServer.Config == nil {
		l.Debug("Preflight for virtual router with ASN not necessary, first instantiation of this BgpServer.")
		return nil
	}

	l.Debug("Begin preflight reoncilation for virtual router with ASN")
	bgpInfo, err := p.CurrentServer.Server.GetBGP(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve BgpServer info for virtual router with ASN %v: %w", p.DesiredConfig.LocalASN, err)
	}

	// parse Node annotations into helper Annotation map
	annoMap, err := agent.NewAnnotationMap(p.CiliumNode.Annotations)
	if err != nil {
		return fmt.Errorf("failed to parse CiliumNode annotations for virtual router with ASN %v: %w", p.DesiredConfig.LocalASN, err)
	}

	// resolve local port from kubernetes annotations
	var localPort int32
	localPort = -1
	if attrs, ok := annoMap[p.DesiredConfig.LocalASN]; ok {
		if attrs.LocalPort != 0 {
			localPort = int32(attrs.LocalPort)
		}
	}

	routerID, err := annoMap.ResolveRouterID(p.DesiredConfig.LocalASN)
	if err != nil {
		if nodeIP := p.CiliumNode.GetIP(false); nodeIP == nil {
			return fmt.Errorf("failed to get ciliumnode IP %v: %w", nodeIP, err)
		} else {
			routerID = nodeIP.String()
		}
	}

	var shouldRecreate bool
	if localPort != bgpInfo.Global.ListenPort {
		shouldRecreate = true
		l.Info(
			"Virtual router with ASN has changed local port",
			types.FromPortLogField, bgpInfo.Global.ListenPort,
			types.ToPortLogField, localPort,
		)
	}
	if routerID != bgpInfo.Global.RouterID {
		shouldRecreate = true
		l.Info(
			"Virtual router with ASN has changed route ID",
			types.FromRouterIDLogField, bgpInfo.Global.RouterID,
			types.ToRouterIDLogField, routerID,
		)
	}
	if !shouldRecreate {
		l.Debug("No preflight reconciliation necessary for virtual router with local ASN")
		return nil
	}

	l.Info("Recreating virtual router with ASN for changes to take effect")
	globalConfig := types.ServerParameters{
		Global: types.BGPGlobal{
			ASN:        uint32(p.DesiredConfig.LocalASN),
			RouterID:   routerID,
			ListenPort: localPort,
			RouteSelectionOptions: &types.RouteSelectionOptions{
				AdvertiseInactiveRoutes: true,
			},
		},
	}

	// stop the old BgpServer
	p.CurrentServer.Server.Stop()

	// create a new one via ServerWithConfig constructor
	s, err := instance.NewServerWithConfig(ctx, r.logger, globalConfig)
	if err != nil {
		l.Error("Failed to start BGP server for virtual router with local ASN", logfields.Error, err)
		return fmt.Errorf("failed to start BGP server for virtual router with local ASN %v: %w", p.DesiredConfig.LocalASN, err)
	}

	// replace the old underlying server with our recreated one
	p.CurrentServer.Server = s.Server

	// dump the existing config so all subsequent reconcilers perform their
	// actions as if this is a new BgpServer.
	p.CurrentServer.Config = nil

	// Clear the shadow state since any advertisements will be gone now that the server has been recreated.
	p.CurrentServer.ReconcilerMetadata = make(map[string]any)

	return nil
}
