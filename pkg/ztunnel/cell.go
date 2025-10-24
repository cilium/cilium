// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ztunnel

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/ztunnel/config"
	"github.com/cilium/cilium/pkg/ztunnel/reconciler"
	"github.com/cilium/cilium/pkg/ztunnel/xds"
	"github.com/cilium/cilium/pkg/ztunnel/zds"
)

// Cell starts ztunnel related control-plane components.
var Cell = cell.Module(
	"ztunnel",
	"ztunnel related control-plane components",
	cell.Config(config.DefaultConfig),
	cell.Invoke(validateConfig),

	// XDS control plane for ztunnel
	xds.Cell,

	// ZDS server for ztunnel
	zds.Cell,
	reconciler.Cell,
)

type ztunnelParams struct {
	cell.In

	Config      config.Config
	ClusterMesh *clustermesh.ClusterMesh
}

func validateConfig(params ztunnelParams) error {
	if !params.Config.EnableZTunnel {
		return nil
	}

	if params.ClusterMesh != nil {
		return fmt.Errorf("ztunnel is not compatible with clustermesh")
	}

	return nil
}
