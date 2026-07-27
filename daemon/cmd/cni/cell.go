// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cni

import (
	"context"
	"log/slog"
	"path"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/daemon/cmd/cni/config"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/option"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
)

var Cell = cell.Module(
	"cni-config",
	"CNI configuration manager",

	config.Cell,
	cell.Provide(enableConfigManager),
)

type CNIConfigManager interface {
	// GetMTU provides the MTU from the provided CNI configuration file.
	// This is only useful if ReadCNIConfiguration is set *and* the file specifies an MTU.
	GetMTU() int

	// GetChainingMode returns the configured CNI chaining mode
	GetChainingMode() string

	// Status returns the status of the CNI manager.
	// Cannot return nil.
	Status() *models.Status

	GetCustomNetConf() *cnitypes.NetConf

	// ExternalRoutingEnabled returns true if the chained plugin implements
	// routing for Endpoints (Pods).
	ExternalRoutingEnabled() bool

	// GetDelegatedIPAMCNIBinPath returns the path to the CNI bin directory
	// used for delegated IPAM plugin invocations.
	GetDelegatedIPAMCNIBinPath() string
}

func enableConfigManager(lc cell.Lifecycle, logger *slog.Logger, cfg config.Config, dcfg *option.DaemonConfig /*only for .Debug*/) CNIConfigManager {
	c := newConfigManager(logger, cfg, dcfg.Debug)
	lc.Append(c)
	return c
}

func newConfigManager(logger *slog.Logger, cfg config.Config, debug bool) *cniConfigManager {
	s := models.Status{
		Msg:   "CNI controller not started",
		State: models.StatusStateFailure,
	}

	c := &cniConfigManager{
		config:     cfg,
		debug:      debug,
		logger:     logger,
		controller: controller.NewManager(),
	}

	c.status.Store(&s)

	c.cniConfDir, c.cniConfFile = path.Split(cfg.WriteCNIConfWhenReady)
	c.ctx, c.doneFunc = context.WithCancel(context.Background())

	return c
}
