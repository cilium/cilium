// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/defaults"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/maps/vtep"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Module(
	"vtep-integration",
	"VXLAN Tunnel Endpoint Integration",

	cell.Config(config{
		VTEPSyncInterval: 1 * time.Minute,
		VTEPEndpoint:     []string{},
		VTEPCIDR:         []string{},
		VTEPMAC:          []string{},
	}),
	cell.Invoke(newVTEPController),
)

type vtepControllerParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group

	VTEPMap   vtep.Map
	Config    config
	Clientset client.Clientset

	// VTEPConfigResource is optional - only available when k8s is enabled
	VTEPConfigResource resource.Resource[*cilium_api_v2.CiliumVTEPConfig] `optional:"true"`
}

func newVTEPController(params vtepControllerParams) error {
	if !option.Config.EnableVTEP {
		return nil
	}

	// Create the manager for route management
	mgr := &vtepManager{
		logger:  params.Logger,
		vtepMap: params.VTEPMap,
		config:  vtepManagerConfig{}, // Will be populated by reconciler or static config
	}

	// Create the reconciler if CRD resource is available
	var reconciler *VTEPReconciler
	if params.VTEPConfigResource != nil {
		reconciler = newVTEPReconciler(vtepReconcilerParams{
			Logger:    params.Logger,
			VTEPMap:   params.VTEPMap,
			Clientset: params.Clientset,
			Resource:  params.VTEPConfigResource,
			Manager:   mgr,
		})
	}

	// Check for ConfigMap-based configuration
	hasConfigMapConfig := len(params.Config.VTEPEndpoint) > 0

	// Initialize controller based on configuration source
	ctrl := &vtepController{
		logger:             params.Logger,
		manager:            mgr,
		reconciler:         reconciler,
		configMapConfig:    params.Config,
		hasConfigMapConfig: hasConfigMapConfig,
		jobGroup:           params.JobGroup,
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			return ctrl.start(ctx)
		},
		OnStop: func(ctx cell.HookContext) error {
			return nil
		},
	})

	return nil
}

// vtepController manages VTEP configuration from either CRD or ConfigMap.
type vtepController struct {
	logger             *slog.Logger
	manager            *vtepManager
	reconciler         *VTEPReconciler
	configMapConfig    config
	hasConfigMapConfig bool
	jobGroup           job.Group
}

// start initializes the VTEP controller based on available configuration sources.
func (c *vtepController) start(ctx context.Context) error {
	// Check if CRD-based configuration is available
	hasCRDConfig := false
	if c.reconciler != nil {
		// Wait briefly for CRD sync before deciding
		syncCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err := c.reconciler.WaitForCRDSync(syncCtx, 5*time.Second); err == nil {
			hasCRDConfig = c.reconciler.HasCRDConfig(ctx)
		}
	}

	switch {
	case hasCRDConfig && c.hasConfigMapConfig:
		// CRD takes precedence, warn about deprecated ConfigMap
		c.logger.Warn("CiliumVTEPConfig CRD found. Ignoring deprecated ConfigMap VTEP settings. " +
			"Please remove vtep-endpoint, vtep-cidr, vtep-mac from your ConfigMap.")
		return c.startCRDReconciler(ctx)

	case hasCRDConfig:
		// CRD only - preferred path
		c.logger.Info("Using CiliumVTEPConfig CRD for VTEP configuration")
		return c.startCRDReconciler(ctx)

	case c.hasConfigMapConfig:
		// ConfigMap only - deprecated but still supported
		c.logger.Warn("DEPRECATED: ConfigMap-based VTEP configuration (vtep-endpoint, vtep-cidr, vtep-mac) " +
			"is deprecated and will be removed in v1.18. Please migrate to CiliumVTEPConfig CRD. " +
			"See https://docs.cilium.io/en/stable/network/vtep/#migration-to-crd")
		return c.startStaticConfigManager(ctx)

	default:
		// No VTEP config - this should not happen as enable-vtep requires config
		return fmt.Errorf("VTEP is enabled but no configuration found. Please provide either " +
			"a CiliumVTEPConfig CRD or ConfigMap-based vtep-endpoint/vtep-cidr/vtep-mac configuration")
	}
}

// startCRDReconciler starts the CRD-based reconciler.
func (c *vtepController) startCRDReconciler(ctx context.Context) error {
	// Do initial sync from CRD
	if err := c.reconciler.SyncFromCRD(ctx); err != nil {
		c.logger.Error("Initial VTEP CRD sync failed", "error", err)
		// Continue anyway, reconciler will retry
	}

	// Start the reconciler job to watch for CRD changes
	c.jobGroup.Add(job.OneShot("vtep-crd-reconciler", func(ctx context.Context, _ cell.Health) error {
		return c.reconciler.Run(ctx)
	}))

	return nil
}

// startStaticConfigManager starts the ConfigMap-based static configuration manager.
func (c *vtepController) startStaticConfigManager(ctx context.Context) error {
	// Validate the ConfigMap configuration
	validatedConfig, err := c.configMapConfig.validatedConfig()
	if err != nil {
		return fmt.Errorf("invalid vtep config: %w", err)
	}

	// Update manager with static config
	c.manager.config = *validatedConfig

	// Start job to setup and periodically verify VTEP endpoints and routes
	tr := job.NewTrigger()
	tr.Trigger()
	c.jobGroup.Add(job.Timer("sync-vtep", c.manager.syncVTEP, 1*time.Minute, job.WithTrigger(tr)))

	return nil
}

type config struct {
	VTEPSyncInterval time.Duration
	VTEPEndpoint     []string
	VTEPCIDR         []string
	VTEPMAC          []string
}

func (r config) Flags(flags *pflag.FlagSet) {
	flags.Duration("vtep-sync-interval", r.VTEPSyncInterval, "Interval for VTEP sync")
	flags.StringSlice("vtep-endpoint", r.VTEPEndpoint, "List of VTEP IP addresses (DEPRECATED: use CiliumVTEPConfig CRD)")
	flags.StringSlice("vtep-cidr", r.VTEPCIDR, "List of VTEP CIDRs that will be routed towards VTEPs for traffic cluster egress (DEPRECATED: use CiliumVTEPConfig CRD)")
	flags.StringSlice("vtep-mac", r.VTEPMAC, "List of VTEP MAC addresses for forwarding traffic outside the cluster (DEPRECATED: use CiliumVTEPConfig CRD)")
}

func (r config) validatedConfig() (*vtepManagerConfig, error) {
	config := vtepManagerConfig{}

	if len(r.VTEPEndpoint) < 1 {
		return nil, fmt.Errorf("if VTEP is enabled, at least one VTEP device must be configured")
	}

	if len(r.VTEPEndpoint) > defaults.MaxVTEPDevices {
		return nil, fmt.Errorf("VTEP must not exceed %d VTEP devices (Found %d VTEPs)", defaults.MaxVTEPDevices, len(r.VTEPEndpoint))
	}

	if len(r.VTEPEndpoint) != len(r.VTEPCIDR) ||
		len(r.VTEPEndpoint) != len(r.VTEPMAC) {
		return nil, fmt.Errorf("VTEP configuration must have the same number of Endpoint, VTEP and MAC configurations (Found %d endpoints, %d MACs, %d CIDR ranges)", len(r.VTEPEndpoint), len(r.VTEPMAC), len(r.VTEPCIDR))
	}

	for _, ep := range r.VTEPEndpoint {
		endpoint := net.ParseIP(ep)
		if endpoint == nil {
			return nil, fmt.Errorf("invalid VTEP IP: %v", ep)
		}
		ip4 := endpoint.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("invalid VTEP IPv4 address %v", ip4)
		}
		config.vtepEndpoints = append(config.vtepEndpoints, endpoint)
	}

	for _, v := range r.VTEPCIDR {
		externalCIDR, err := cidr.ParseCIDR(v)
		if err != nil {
			return nil, fmt.Errorf("invalid VTEP CIDR: %v", v)
		}
		config.vtepCIDRs = append(config.vtepCIDRs, externalCIDR)
	}

	for _, m := range r.VTEPMAC {
		externalMAC, err := mac.ParseMAC(m)
		if err != nil {
			return nil, fmt.Errorf("invalid VTEP MAC: %v", m)
		}
		config.vtepMACs = append(config.vtepMACs, externalMAC)
	}

	return &config, nil
}
