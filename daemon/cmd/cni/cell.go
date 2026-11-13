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
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
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
}

// DatapathReady signals that the datapath is ready to create endpoints.
type DatapathReady struct{}

type configManagerParams struct {
	cell.In

	Lifecycle    cell.Lifecycle
	Logger       *slog.Logger
	Config       config.Config
	KPRConfig    kpr.KPRConfig
	DaemonConfig *option.DaemonConfig // only for .Debug
	// todo(ekoops): remove this once BPF objects get pre-compiled.
	// DatapathReady keeps the agent not ready, and holds back the writing of a missing CNI
	// configuration, until it is resolved, so that no pod is scheduled or created earlier.
	DatapathReady promise.Promise[DatapathReady]
}

func enableConfigManager(p configManagerParams) CNIConfigManager {
	c := newConfigManager(p.Logger, p.Config, p.DaemonConfig.Debug)
	c.kubeProxyReplacement = p.KPRConfig.KubeProxyReplacement
	c.datapathReady = p.DatapathReady
	p.Lifecycle.Append(c)
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
