// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/hive/cell"
)

// PreflightReconciler reconciles BPG Global configuration. This reconciler is similar to v1 preflight reconciler.
// It must be run before any other reconcilers for given BGP instance.
type PreflightReconciler struct {
	Logger logrus.FieldLogger
}

type PreflightReconcilerIn struct {
	cell.In

	Logger logrus.FieldLogger
}

type PreflightReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

func NewPreflightReconciler(params PreflightReconcilerIn) PreflightReconcilerOut {
	logger := params.Logger.WithField(types.ReconcilerLogField, "Preflight")
	return PreflightReconcilerOut{
		Reconciler: &PreflightReconciler{
			Logger: logger,
		},
	}
}

func (r *PreflightReconciler) Name() string {
	return "Preflight"
}

func (r *PreflightReconciler) Priority() int {
	return 10
}

func (r *PreflightReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	l := r.Logger.WithFields(logrus.Fields{
		types.InstanceLogField: p.DesiredConfig.Name,
	})

	// If we have no config attached, we don't need to perform a preflight for
	// reconciliation.
	//
	// This is the first time this instance is being registered and BGPRouterManager
	// set any fields needing reconciliation in this function already.
	if p.BGPInstance.Config == nil {
		l.Debug("Preflight for instance not necessary, first instantiation of this BgpServer.")
		return nil
	}

	l.Debug("Begin preflight reconciliation")
	bgpInfo, err := p.BGPInstance.Router.GetBGP(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve BgpServer info for instance %v: %w", p.DesiredConfig.Name, err)
	}

	localASN, err := r.getLocalASN(p)
	if err != nil {
		return fmt.Errorf("failed to get local ASN for instance %v: %w", p.DesiredConfig.Name, err)
	}

	localPort, err := r.getLocalPort(p, localASN)
	if err != nil {
		return fmt.Errorf("failed to get local port for instance %v: %w", p.DesiredConfig.Name, err)
	}

	routerID, err := r.getRouterID(p, localASN)
	if err != nil {
		return fmt.Errorf("failed to get router ID for instance %v: %w", p.DesiredConfig.Name, err)
	}

	var shouldRecreate bool
	if localASN != int64(bgpInfo.Global.ASN) {
		shouldRecreate = true
		l.WithFields(logrus.Fields{
			types.LocalASNLogField: bgpInfo.Global.ASN,
			"new_asn":              localASN,
		}).Info("BGP instance ASN modified")
	}
	if localPort != bgpInfo.Global.ListenPort {
		shouldRecreate = true
		l.WithFields(logrus.Fields{
			types.ListenPortLogField: bgpInfo.Global.ListenPort,
			"new_port":               localPort,
		}).Info("BGP instance local port modified")
	}
	if routerID != bgpInfo.Global.RouterID {
		shouldRecreate = true
		l.WithFields(logrus.Fields{
			types.RouterIDLogField: bgpInfo.Global.RouterID,
			"new_router_id":        routerID,
		}).Info("BGP instance router ID modified")
	}

	if !shouldRecreate {
		l.Debug("No preflight reconciliation necessary")
		return nil
	}

	l.Info("Recreating BGP instance for changes to take effect")
	globalConfig := types.ServerParameters{
		Global: types.BGPGlobal{
			ASN:        uint32(localASN),
			RouterID:   routerID,
			ListenPort: localPort,
			RouteSelectionOptions: &types.RouteSelectionOptions{
				AdvertiseInactiveRoutes: true,
			},
		},
	}

	// stop the old BGP instance
	p.BGPInstance.Router.Stop()

	// create a new one via BGPInstance constructor
	s, err := instance.NewBGPInstance(ctx, l, globalConfig)
	if err != nil {
		return fmt.Errorf("failed to start BGP instance for %s: %w", p.DesiredConfig.Name, err)
	}

	// replace the old underlying instance with our recreated one
	p.BGPInstance.Router = s.Router

	// dump the existing config so all subsequent reconcilers perform their
	// actions as if this is a new instance.
	p.BGPInstance.Config = nil

	// Clear the shadow state since any peer, advertisements will be gone now that the instance has been recreated.
	p.BGPInstance.Metadata = make(map[string]any)

	return nil
}

// getLocalASN returns the local ASN for the given BGP instance. If the local ASN is defined in the desired config, it
// will be returned. Currently, we do not support auto-ASN assignment, so if the local ASN is not defined in the
// desired config, an error will be returned.
func (r *PreflightReconciler) getLocalASN(p ReconcileParams) (int64, error) {
	if p.DesiredConfig.LocalASN != nil {
		return *p.DesiredConfig.LocalASN, nil
	}

	return -1, fmt.Errorf("missing ASN in desired config")
}

// getRouterID returns the router ID for the given ASN. If the router ID is defined in the desired config, it will
// be returned. Otherwise, the router ID will be resolved from the ciliumnode annotations. If the router ID is not
// defined in the annotations, the node IP from cilium node will be returned.
func (r *PreflightReconciler) getRouterID(p ReconcileParams, asn int64) (string, error) {
	if p.DesiredConfig.RouterID != nil {
		return *p.DesiredConfig.RouterID, nil
	}

	// parse Node annotations into helper Annotation map
	annoMap, err := agent.NewAnnotationMap(p.CiliumNode.Annotations)
	if err != nil {
		return "", fmt.Errorf("failed to parse Node annotations for instance %v: %w", p.DesiredConfig.Name, err)
	}

	routerID, err := annoMap.ResolveRouterID(asn)
	if err != nil {
		if nodeIP := p.CiliumNode.GetIP(false); nodeIP == nil {
			return "", fmt.Errorf("failed to get ciliumnode IP %v: %w", nodeIP, err)
		} else {
			routerID = nodeIP.String()
		}
	}

	return routerID, nil
}

// getLocalPort returns the local port for the given ASN. If the local port is defined in the desired config, it will
// be returned. Otherwise, the local port will be resolved from the ciliumnode annotations. If the local port is not
// defined in the annotations, -1 will be returned.
//
// In gobgp, with -1 as the local port, bgp instance will start in non-listening mode.
func (r *PreflightReconciler) getLocalPort(p ReconcileParams, asn int64) (int32, error) {
	if p.DesiredConfig.LocalPort != nil {
		return *p.DesiredConfig.LocalPort, nil
	}

	// parse Node annotations into helper Annotation map
	annoMap, err := agent.NewAnnotationMap(p.CiliumNode.Annotations)
	if err != nil {
		return -1, fmt.Errorf("failed to parse Node annotations for instance %v: %w", p.DesiredConfig.Name, err)
	}

	localPort := int32(-1)
	if attrs, ok := annoMap[asn]; ok {
		if attrs.LocalPort != 0 {
			localPort = attrs.LocalPort
		}
	}

	return localPort, nil
}
