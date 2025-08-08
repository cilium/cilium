package vtep

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	vtepMap "github.com/cilium/cilium/pkg/maps/vtep"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"vtep",
	"VXLAN Tunnel Endpoint",

	cell.Invoke(syncVTEP),
)

type vtepSync struct {
	logger       *slog.Logger
	routeManager *reconciler.DesiredRouteManager
	db           *statedb.DB
	devices      statedb.Table[*tables.Device]

	owner *reconciler.RouteOwner
}

func syncVTEP(
	logger *slog.Logger,
	jobGroup job.Group,
	config *option.DaemonConfig,
	routeManager *reconciler.DesiredRouteManager,
	db *statedb.DB,
	devices statedb.Table[*tables.Device],
	metricsRegistry *metrics.Registry,
) error {
	if !config.EnableVTEP {
		return nil
	}

	vtep := &vtepSync{
		logger:       logger,
		routeManager: routeManager,
		db:           db,
		devices:      devices,
	}

	if config.EnableL7Proxy {
		owner, err := vtep.routeManager.RegisterOwner("vtep", reconciler.AdminDistanceDefault)
		if err != nil {
			return err
		}

		vtep.owner = owner
		jobGroup.Add(job.OneShot("vtep-routes-and-rules", vtep.syncVTEPRoutesAndRules))
	}

	jobGroup.Add(job.Timer("vtep-mapping", func(_ context.Context) error {
		return setupVTEPMapping(logger, metricsRegistry)
	}, 1*time.Minute))

	return nil
}

func setupVTEPMapping(logger *slog.Logger, registry *metrics.Registry) error {
	for i, ep := range option.Config.VtepEndpoints {
		logger.Debug(
			"Updating vtep map entry for VTEP",
			logfields.IPAddr, ep,
		)

		vtepCidr := cidr.CIDR{IPNet: netipx.PrefixIPNet(option.Config.VtepCIDRs[i])}
		err := vtepMap.UpdateVTEPMapping(logger, registry, &vtepCidr, ep, option.Config.VtepMACs[i])
		if err != nil {
			return fmt.Errorf("Unable to set up VTEP ipcache mappings: %w", err)
		}
	}
	return nil
}

func (vtep *vtepSync) syncVTEPRoutesAndRules(ctx context.Context, health cell.Health) error {
	for {
		rxn := vtep.db.ReadTxn()

		hostDev, _, devWatch, found := vtep.devices.GetWatch(rxn, tables.DeviceNameIndex.Query(defaults.HostDevice))
		if !found {
			health.Degraded("Cannot create VTEP routes", fmt.Errorf("host device %q not found", defaults.HostDevice))
		}

		// TODO(dylandreimerink): Is this correct? Shouldn't we use the detected/configured Device MTU instead of EthernetMTU?
		vtepMTU := mtu.EthernetMTU - mtu.TunnelOverheadIPv4

		var errs error
		for _, vtepCidr := range option.Config.VtepCIDRs {
			err := vtep.routeManager.UpsertRouteWait(reconciler.DesiredRoute{
				Owner:  vtep.owner,
				Prefix: vtepCidr,
				Device: hostDev,
				Scope:  reconciler.SCOPE_LINK,
				Table:  linux_defaults.RouteTableVtep,
				MTU:    uint32(vtepMTU),
			})
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to upsert VTEP route %s: %w", vtepCidr, err))
				continue
			}

			vtep.logger.Info(
				"VTEP route added",
				logfields.IPAddr, vtepCidr,
			)

			rule := route.Rule{
				Priority: linux_defaults.RulePriorityVtep,
				To:       netipx.PrefixIPNet(vtepCidr),
				Table:    linux_defaults.RouteTableVtep,
			}
			if err := route.ReplaceRule(rule); err != nil {
				errs = errors.Join(errs, fmt.Errorf("failed to replace VTEP rule: %w", err))
			}
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-devWatch:
		}
	}
}
