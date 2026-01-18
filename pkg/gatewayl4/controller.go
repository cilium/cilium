// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gatewayl4

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/shortener"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

const (
	gatewayL4ControllerInitName = "gateway-l4-controller"
	waitTime                    = 100 * time.Millisecond
)

type gatewayL4ControllerParams struct {
	cell.In

	Log      *slog.Logger
	DB       *statedb.DB
	JobGroup job.Group
	Configs  statedb.Table[*GatewayL4Config]
	Writer   *writer.Writer
}

type gatewayL4Controller struct {
	p      gatewayL4ControllerParams
	lbInit func(writer.WriteTxn)
}

func registerGatewayL4Controller(p gatewayL4ControllerParams) {
	// Register load-balancing initializer. This will also delay initial
	// endpoint regeneration until we're done.
	lbInit := p.Writer.RegisterInitializer(gatewayL4ControllerInitName)

	h := &gatewayL4Controller{
		p:      p,
		lbInit: lbInit,
	}
	p.JobGroup.Add(job.OneShot(gatewayL4ControllerInitName, h.run))
}

func (c *gatewayL4Controller) run(ctx context.Context, health cell.Health) error {
	txn := c.p.DB.ReadTxn()
	_, cfgInitWatch := c.p.Configs.Initialized(txn)
	initWatches := statedb.NewWatchSet()
	initWatches.Add(cfgInitWatch)

	for {
		allWatches := statedb.NewWatchSet()
		if initWatches != nil {
			allWatches.Merge(initWatches)
		}

		// Start write transaction for LB writer
		wtxn := c.p.Writer.WriteTxn()

		// Build desired state: insert backends with weights
		c.processGatewayL4(wtxn, allWatches)

		if initWatches != nil && chanIsClosed(cfgInitWatch) {
			c.lbInit(wtxn)
			initWatches = nil
		}

		wtxn.Commit()

		if _, err := allWatches.Wait(ctx, waitTime); err != nil {
			return err
		}
	}
}

// processGatewayL4 processes all Gateway L4 configs and upserts backends with weights
func (c *gatewayL4Controller) processGatewayL4(wtxn writer.WriteTxn, watches *statedb.WatchSet) {
	cfgs, watch := c.p.Configs.AllWatch(wtxn)
	watches.Add(watch)

	for cfg := range cfgs {
		if cfg.Spec == nil {
			continue
		}

		// Get the Gateway service name
		gwServiceName, ok := gwServiceName(cfg)
		if !ok {
			c.p.Log.Warn("Skipping Gateway with empty gateway reference",
				logfields.K8sNamespace, cfg.Name.Namespace,
				logfields.Name, cfg.Name.Name)
			continue
		}

		// Watch the Gateway service (to trigger updates when it changes)
		_, _, svcWatch, _ := c.p.Writer.Services().GetWatch(wtxn, loadbalancer.ServiceByName(gwServiceName))
		watches.Add(svcWatch)

		// Track all backends with deduplication (map address -> backend with merged PortNames)
		backendMap := make(map[loadbalancer.L3n4Addr]*loadbalancer.BackendParams)

		// Process each listener in the config
		for _, listener := range cfg.Spec.Listeners {
			proto, err := loadbalancer.NewL4Type(string(listener.Protocol))
			if err != nil {
				c.p.Log.Warn("Skipping Gateway listener with invalid protocol",
					logfields.K8sNamespace, cfg.Name.Namespace,
					logfields.Gateway, cfg.Name.Name,
					logfields.Name, listener.Name,
					logfields.Error, err)
				continue
			}

			// Collect backends for this listener, merging into backendMap to avoid duplicates
			c.collectBackends(wtxn, watches, listener, proto, backendMap)
		}

		// Convert map to slice for upserting
		currentBackends := make([]loadbalancer.BackendParams, 0, len(backendMap))
		for _, params := range backendMap {
			currentBackends = append(currentBackends, *params)
		}

		if err := c.upsertGWBackends(wtxn, gwServiceName, currentBackends); err != nil {
			c.p.Log.Error("Failed to upsert gateway backends",
				logfields.ServiceName, gwServiceName,
				logfields.Error, err)
		}
	}
}

// collectBackends collects backends from referenced services and applies route-specified weights.
// Backends are merged into the provided backendMap to deduplicate across listeners.
func (c *gatewayL4Controller) collectBackends(
	txn writer.WriteTxn,
	watches *statedb.WatchSet,
	listener ciliumv2alpha1.CiliumGatewayL4Listener,
	proto loadbalancer.L4Type,
	backendMap map[loadbalancer.L3n4Addr]*loadbalancer.BackendParams,
) {
	// Generate the Gateway service port name based on the listener's port and protocol.
	// This matches the naming convention used by the operator when creating the Gateway service.
	// TCP: "port-<number>", UDP: "port-<number>-udp"
	var gatewayPortName string
	if proto == loadbalancer.UDP {
		gatewayPortName = fmt.Sprintf("port-%d-udp", listener.Port)
	} else {
		gatewayPortName = fmt.Sprintf("port-%d", listener.Port)
	}

	for _, be := range listener.Backends {
		backendService := loadbalancer.NewServiceName(be.Namespace, be.Name)
		bes, beWatch := c.p.Writer.Backends().ListWatch(txn, loadbalancer.BackendByServiceName(backendService))
		watches.Add(beWatch)

		for backend := range bes {
			inst := backend.GetInstance(backendService)
			if inst == nil {
				continue
			}
			if inst.Address.Protocol() != proto {
				continue
			}

			// Check if backend already exists (from another listener)
			if existing, exists := backendMap[inst.Address]; exists {
				// Merge PortNames from multiple listeners
				existing.PortNames = append(existing.PortNames, gatewayPortName)
			} else {
				// Add new backend
				backendMap[inst.Address] = &loadbalancer.BackendParams{
					Address:   inst.Address,
					Weight:    *be.Weight,
					PortNames: []string{gatewayPortName},
					State:     inst.State,
					NodeName:  inst.NodeName,
					Source:    source.CustomResource,
				}
			}
		}
	}
}

// upsertGWBackends adds backends to the Gateway service and removes stale ones
func (c *gatewayL4Controller) upsertGWBackends(
	wtxn writer.WriteTxn,
	gatewayServiceName loadbalancer.ServiceName,
	backendParams []loadbalancer.BackendParams,
) error {
	// Get current backends for this Gateway
	currentBackends := make(map[loadbalancer.L3n4Addr]loadbalancer.BackendParams)
	bes, _ := c.p.Writer.BackendsForService(wtxn, gatewayServiceName)
	for be := range bes {
		if be.Source == source.CustomResource {
			currentBackends[be.Address] = be
		}
	}

	// Build new backends map
	newBackends := make(map[loadbalancer.L3n4Addr]struct{}, len(backendParams))
	for _, params := range backendParams {
		newBackends[params.Address] = struct{}{}
	}

	// Find orphaned backends (in current but not in new)
	var orphanedAddrs []loadbalancer.L3n4Addr
	for addr := range currentBackends {
		if _, exists := newBackends[addr]; !exists {
			orphanedAddrs = append(orphanedAddrs, addr)
		}
	}

	// Check if backends changed
	if len(orphanedAddrs) == 0 && len(backendParams) == len(currentBackends) {
		allMatch := true
		for _, newParams := range backendParams {
			currentParams, exists := currentBackends[newParams.Address]
			if !exists {
				allMatch = false
				break
			}
			// Compare all relevant fields
			if !newParams.DeepEqual(&currentParams) {
				allMatch = false
				break
			}
		}
		if allMatch {
			// No changes, skip upsert
			return nil
		}
	}

	backends := func(yield func(loadbalancer.BackendParams) bool) {
		for _, params := range backendParams {
			if !yield(params) {
				return
			}
		}
	}

	orphans := func(yield func(loadbalancer.L3n4Addr) bool) {
		for _, addr := range orphanedAddrs {
			if !yield(addr) {
				return
			}
		}
	}

	// Upsert new backends and release orphaned ones
	return c.p.Writer.UpsertAndReleaseBackends(wtxn, gatewayServiceName, source.CustomResource, backends, orphans)
}

const gatewayServiceNamePrefix = "cilium-gateway-"

func gwServiceName(cfg *GatewayL4Config) (loadbalancer.ServiceName, bool) {
	if cfg.Spec == nil || cfg.Spec.GatewayRef.Name == "" {
		return loadbalancer.ServiceName{}, false
	}
	namespace := cfg.Spec.GatewayRef.Namespace
	if namespace == "" {
		namespace = cfg.Name.Namespace
	}
	name := shortener.ShortenK8sResourceName(gatewayServiceNamePrefix + cfg.Spec.GatewayRef.Name)
	return loadbalancer.NewServiceName(namespace, name), true
}

func chanIsClosed(ch <-chan struct{}) bool {
	if ch == nil {
		return true
	}
	select {
	case _, ok := <-ch:
		return !ok
	default:
		return false
	}
}
