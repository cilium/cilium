// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/defaults"
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
	cell.Invoke(newVTEPManager),
)

type vtepManagerParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group

	VTEPMap vtep.Map
	Config  config
}

func newVTEPManager(params vtepManagerParams) error {
	if !option.Config.EnableVTEP {
		return nil
	}

	validatedConfig, err := params.Config.validatedConfig()
	if err != nil {
		return fmt.Errorf("invalid vtep config: %w", err)
	}

	mgr := &vtepManager{
		logger:  params.Logger,
		vtepMap: params.VTEPMap,
		config:  *validatedConfig,
	}

	// Start job to setup and periodically verify VTEP endpoints and routes.

	// use trigger to enforce first execution immediately when the timer job starts
	tr := job.NewTrigger()
	tr.Trigger()
	params.JobGroup.Add(job.Timer("sync-vtep", mgr.syncVTEP, 1*time.Minute, job.WithTrigger(tr)))

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
	flags.StringSlice("vtep-endpoint", r.VTEPEndpoint, "List of VTEP IP addresses")
	flags.StringSlice("vtep-cidr", r.VTEPCIDR, "List of VTEP CIDRs that will be routed towards VTEPs for traffic cluster egress")
	flags.StringSlice("vtep-mac", r.VTEPMAC, "List of VTEP MAC addresses for forwarding traffic outside the cluster")
}

func (r config) validatedConfig() (*vtepManagerConfig, error) {
	config := vtepManagerConfig{}

	if len(r.VTEPEndpoint) < 1 {
		return nil, fmt.Errorf("If VTEP is enabled, at least one VTEP device must be configured")
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
			return nil, fmt.Errorf("Invalid VTEP IP: %v", ep)
		}
		ip4 := endpoint.To4()
		if ip4 == nil {
			return nil, fmt.Errorf("Invalid VTEP IPv4 address %v", ip4)
		}
		config.vtepEndpoints = append(config.vtepEndpoints, endpoint)
	}

	for _, v := range r.VTEPCIDR {
		externalCIDR, err := cidr.ParseCIDR(v)
		if err != nil {
			return nil, fmt.Errorf("Invalid VTEP CIDR: %v", v)
		}
		config.vtepCIDRs = append(config.vtepCIDRs, externalCIDR)
	}

	for _, m := range r.VTEPMAC {
		externalMAC, err := mac.ParseMAC(m)
		if err != nil {
			return nil, fmt.Errorf("Invalid VTEP MAC: %v", m)
		}
		config.vtepMACs = append(config.vtepMACs, externalMAC)
	}

	return &config, nil
}
