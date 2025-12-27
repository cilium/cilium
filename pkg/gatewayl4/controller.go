// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gatewayl4

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/shortener"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/time"
)

const (
	gatewayL4ControllerInitName = "gateway-l4-controller"
	maxGatewayL4BackendWeight   = int32(^uint16(0))
)

type gatewayL4ControllerParams struct {
	cell.In

	Log     *slog.Logger
	DB      *statedb.DB
	Configs statedb.Table[*GatewayL4Config]
	Writer  *writer.Writer
}

type gatewayL4Controller struct {
	p              gatewayL4ControllerParams
	lbInit         func(writer.WriteTxn)
	ownedServices  map[loadbalancer.ServiceName]struct{}
	ownedRedirects map[loadbalancer.L3n4Addr]loadbalancer.ServiceName
}

func registerGatewayL4Controller(g job.Group, p gatewayL4ControllerParams) {
	if p.Writer == nil {
		return
	}

	lbInit := p.Writer.RegisterInitializer(gatewayL4ControllerInitName)
	h := &gatewayL4Controller{
		p:              p,
		lbInit:         lbInit,
		ownedServices:  map[loadbalancer.ServiceName]struct{}{},
		ownedRedirects: map[loadbalancer.L3n4Addr]loadbalancer.ServiceName{},
	}
	g.Add(job.OneShot("gateway-l4-controller", h.run))
}

func (c *gatewayL4Controller) run(ctx context.Context, health cell.Health) error {
	const waitTime = 100 * time.Millisecond

	txn := c.p.DB.ReadTxn()
	_, cfgInitWatch := c.p.Configs.Initialized(txn)
	initWatches := statedb.NewWatchSet()
	initWatches.Add(cfgInitWatch)

	for {
		allWatches := statedb.NewWatchSet()
		if initWatches != nil {
			allWatches.Merge(initWatches)
		}

		wtxn := c.p.Writer.WriteTxn()

		desired, redirects, l4ToGateway, watch := c.buildDesiredState(wtxn, allWatches)
		allWatches.Add(watch)

		c.applyDesiredState(wtxn, desired, redirects, l4ToGateway)

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

type gatewayL4Desired struct {
	service   *loadbalancer.Service
	frontends map[loadbalancer.L3n4Addr]loadbalancer.FrontendParams
	backends  map[loadbalancer.L3n4Addr]loadbalancer.BackendParams
}

type gatewayL4ListenerKey struct {
	port  uint16
	proto loadbalancer.L4Type
}

func (c *gatewayL4Controller) buildDesiredState(txn writer.WriteTxn, watches *statedb.WatchSet) (map[loadbalancer.ServiceName]*gatewayL4Desired, map[loadbalancer.L3n4Addr]loadbalancer.ServiceName, map[loadbalancer.ServiceName]loadbalancer.ServiceName, <-chan struct{}) {
	cfgs, watch := c.p.Configs.AllWatch(txn)

	desired := map[loadbalancer.ServiceName]*gatewayL4Desired{}
	redirects := map[loadbalancer.L3n4Addr]loadbalancer.ServiceName{}
	l4ToGateway := map[loadbalancer.ServiceName]loadbalancer.ServiceName{}

	for cfg := range cfgs {
		if cfg.Spec == nil {
			continue
		}
		gatewayServiceName, ok := gatewayL4GatewayServiceName(cfg)
		if !ok {
			c.p.Log.Warn("Skipping Gateway L4 config with empty gateway reference",
				cfg.Name.MarshalLog())
			continue
		}
		gatewayFrontends, gatewayFrontendsWatch := c.p.Writer.Frontends().ListWatch(txn, loadbalancer.FrontendByServiceName(gatewayServiceName))
		watches.Add(gatewayFrontendsWatch)

		gatewayFrontendsList := make([]*loadbalancer.Frontend, 0)
		for fe := range gatewayFrontends {
			gatewayFrontendsList = append(gatewayFrontendsList, fe)
		}

		listenerTargets := map[gatewayL4ListenerKey]loadbalancer.ServiceName{}
		for _, listener := range cfg.Spec.Listeners {
			proto, err := loadbalancer.NewL4Type(string(listener.Protocol))
			if err != nil {
				c.p.Log.Warn("Skipping Gateway L4 listener with invalid protocol",
					logfields.Name, listener.Name,
					logfields.Error, err)
				continue
			}

			serviceName := gatewayL4ServiceName(cfg, listener.Name)
			l4ToGateway[serviceName] = gatewayServiceName
			listenerTargets[gatewayL4ListenerKey{port: uint16(listener.Port), proto: proto}] = serviceName
			entry := desired[serviceName]
			if entry == nil {
				entry = &gatewayL4Desired{
					service:   newGatewayL4Service(serviceName),
					frontends: map[loadbalancer.L3n4Addr]loadbalancer.FrontendParams{},
					backends:  map[loadbalancer.L3n4Addr]loadbalancer.BackendParams{},
				}
				desired[serviceName] = entry
			}

			for _, be := range listener.Backends {
				weight := int32(1)
				if be.Weight != nil {
					weight = *be.Weight
				}
				if weight <= 0 {
					continue
				}
				if weight > maxGatewayL4BackendWeight {
					c.p.Log.Warn("Backend weight exceeds max, clamping",
						logfields.ServiceName, serviceName,
						logfields.BackendName, be.Name,
						logfields.Value, weight)
					weight = maxGatewayL4BackendWeight
				}

				backendNS := be.Namespace
				if backendNS == "" {
					backendNS = cfg.Name.Namespace
				}
				backendService := loadbalancer.NewServiceName(backendNS, be.Name)
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

					newParams := *inst
					newParams.Weight = uint16(weight)
					// Avoid port-name filtering on redirect frontends; port/protocol already match.
					newParams.PortNames = nil
					if prev, ok := entry.backends[newParams.Address]; ok {
						if prev.Weight < newParams.Weight {
							entry.backends[newParams.Address] = newParams
						}
						continue
					}
					entry.backends[newParams.Address] = newParams
				}
			}
		}

		for _, fe := range gatewayFrontendsList {
			key := gatewayL4ListenerKey{port: fe.ServicePort, proto: fe.Address.Protocol()}
			if target, ok := listenerTargets[key]; ok {
				redirects[fe.Address] = target
			}
		}
	}

	return desired, redirects, l4ToGateway, watch
}

func (c *gatewayL4Controller) applyDesiredState(txn writer.WriteTxn, desired map[loadbalancer.ServiceName]*gatewayL4Desired, redirects map[loadbalancer.L3n4Addr]loadbalancer.ServiceName, l4ToGateway map[loadbalancer.ServiceName]loadbalancer.ServiceName) {
	refreshed := map[loadbalancer.ServiceName]struct{}{}

	for name := range desired {
		c.ownedServices[name] = struct{}{}
	}

	for name := range c.ownedServices {
		if _, ok := desired[name]; ok {
			continue
		}
		if err := c.p.Writer.DeleteBackendsOfService(txn, name, source.CustomResource); err != nil {
			c.p.Log.Warn("Failed to delete Gateway L4 backends",
				logfields.ServiceName, name,
				logfields.Error, err)
			continue
		}
		if _, err := c.p.Writer.DeleteServiceAndFrontends(txn, name); err != nil {
			if errors.Is(err, statedb.ErrObjectNotFound) {
				delete(c.ownedServices, name)
				continue
			}
			c.p.Log.Warn("Failed to delete Gateway L4 service",
				logfields.ServiceName, name,
				logfields.Error, err)
			continue
		}
		delete(c.ownedServices, name)
	}

	for name, entry := range desired {
		if entry.service != nil {
			shouldUpsert := true
			if existing, _, found := c.p.Writer.Services().Get(txn, loadbalancer.ServiceByName(name)); found {
				shouldUpsert = !gatewayL4ServiceEqual(existing, entry.service)
			}
			if shouldUpsert {
				if _, err := c.p.Writer.UpsertService(txn, entry.service); err != nil {
					c.p.Log.Warn("Failed to upsert Gateway L4 service",
						logfields.ServiceName, name,
						logfields.Error, err)
					continue
				}
			}
		}

		existingFEs := map[loadbalancer.L3n4Addr]struct{}{}
		for fe := range c.p.Writer.Frontends().List(txn, loadbalancer.FrontendByServiceName(name)) {
			existingFEs[fe.Address] = struct{}{}
			if _, ok := entry.frontends[fe.Address]; !ok {
				c.p.Writer.DeleteFrontend(txn, fe.Address)
			}
		}
		for addr, fe := range entry.frontends {
			if _, ok := existingFEs[addr]; !ok {
				if _, err := c.p.Writer.UpsertFrontend(txn, fe); err != nil {
					c.p.Log.Warn("Failed to upsert Gateway L4 frontend",
						logfields.ServiceName, name,
						logfields.Address, addr.StringWithProtocol(),
						logfields.Error, err)
				}
			}
		}

		if !c.gatewayL4BackendsEqual(txn, name, entry.backends) {
			backends := make([]loadbalancer.BackendParams, 0, len(entry.backends))
			for _, be := range entry.backends {
				backends = append(backends, be)
			}
			if err := c.p.Writer.SetBackends(txn, name, source.CustomResource, backends...); err != nil {
				c.p.Log.Warn("Failed to set Gateway L4 backends",
					logfields.ServiceName, name,
					logfields.Error, err)
			} else if gatewayName, ok := l4ToGateway[name]; ok {
				if _, ok := refreshed[gatewayName]; !ok {
					if err := c.p.Writer.RefreshFrontends(txn, gatewayName); err != nil {
						c.p.Log.Warn("Failed to refresh Gateway L4 frontends",
							logfields.ServiceName, gatewayName,
							logfields.Error, err)
					}
					refreshed[gatewayName] = struct{}{}
				}
			}
		}
	}

	c.applyGatewayL4Redirects(txn, redirects)
}

func (c *gatewayL4Controller) applyGatewayL4Redirects(txn writer.WriteTxn, desired map[loadbalancer.L3n4Addr]loadbalancer.ServiceName) {
	if c.ownedRedirects == nil {
		c.ownedRedirects = map[loadbalancer.L3n4Addr]loadbalancer.ServiceName{}
	}

	for addr, target := range desired {
		fe, _, found := c.p.Writer.Frontends().Get(txn, loadbalancer.FrontendByAddress(addr))
		if !found {
			continue
		}

		if fe.RedirectTo != nil && !fe.RedirectTo.Equal(target) {
			if prev, ok := c.ownedRedirects[addr]; !ok || !prev.Equal(*fe.RedirectTo) {
				continue
			}
		}

		if fe.RedirectTo == nil || !fe.RedirectTo.Equal(target) {
			targetCopy := target
			c.p.Writer.SetRedirectTo(txn, fe, &targetCopy)
		}
		c.ownedRedirects[addr] = target
	}

	for addr, prev := range c.ownedRedirects {
		if _, ok := desired[addr]; ok {
			continue
		}
		fe, _, found := c.p.Writer.Frontends().Get(txn, loadbalancer.FrontendByAddress(addr))
		if !found {
			delete(c.ownedRedirects, addr)
			continue
		}
		if fe.RedirectTo != nil && fe.RedirectTo.Equal(prev) {
			c.p.Writer.SetRedirectTo(txn, fe, nil)
		}
		delete(c.ownedRedirects, addr)
	}
}

func newGatewayL4Service(name loadbalancer.ServiceName) *loadbalancer.Service {
	return &loadbalancer.Service{
		Name:             name,
		Source:           source.CustomResource,
		ExtTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
		IntTrafficPolicy: loadbalancer.SVCTrafficPolicyCluster,
	}
}

const gatewayServiceNamePrefix = "cilium-gateway-"

func gatewayL4GatewayServiceName(cfg *GatewayL4Config) (loadbalancer.ServiceName, bool) {
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

func gatewayL4ServiceName(cfg *GatewayL4Config, listenerName string) loadbalancer.ServiceName {
	name := cfg.Name.Name
	if listenerName != "" {
		name = fmt.Sprintf("%s-%s", name, listenerName)
	}
	name = shortener.ShortenK8sResourceName(name)
	return loadbalancer.NewServiceName(cfg.Name.Namespace, name)
}

func gatewayL4ServiceEqual(current, desired *loadbalancer.Service) bool {
	if current == nil || desired == nil {
		return current == desired
	}
	return current.Name == desired.Name &&
		current.Source == desired.Source &&
		current.ExtTrafficPolicy == desired.ExtTrafficPolicy &&
		current.IntTrafficPolicy == desired.IntTrafficPolicy
}

func (c *gatewayL4Controller) gatewayL4BackendsEqual(txn statedb.ReadTxn, name loadbalancer.ServiceName, desired map[loadbalancer.L3n4Addr]loadbalancer.BackendParams) bool {
	desiredNormalized := make(map[loadbalancer.L3n4Addr]loadbalancer.BackendParams, len(desired))
	for addr, be := range desired {
		desiredNormalized[addr] = normalizeGatewayL4Backend(be)
	}

	currentCount := 0
	for backend := range c.p.Writer.Backends().List(txn, loadbalancer.BackendByServiceName(name)) {
		inst := backend.GetInstanceFromSource(name, source.CustomResource)
		if inst == nil {
			continue
		}
		currentCount++

		desiredParams, ok := desiredNormalized[inst.Address]
		if !ok {
			return false
		}
		if !gatewayL4BackendEqual(normalizeGatewayL4Backend(*inst), desiredParams) {
			return false
		}
	}

	return currentCount == len(desiredNormalized)
}

func normalizeGatewayL4Backend(be loadbalancer.BackendParams) loadbalancer.BackendParams {
	be.Source = source.CustomResource
	be.ClusterID = 0
	be.Unhealthy = false
	be.UnhealthyUpdatedAt = nil
	if len(be.PortNames) == 0 {
		be.PortNames = nil
	}
	return be
}

func gatewayL4BackendEqual(a, b loadbalancer.BackendParams) bool {
	if a.Address != b.Address {
		return false
	}
	if a.Weight != b.Weight {
		return false
	}
	if a.NodeName != b.NodeName {
		return false
	}
	if a.ClusterID != b.ClusterID {
		return false
	}
	if a.State != b.State {
		return false
	}
	if !slices.Equal(a.PortNames, b.PortNames) {
		return false
	}
	return backendZonesEqual(a.Zone, b.Zone)
}

func backendZonesEqual(a, b *loadbalancer.BackendZone) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.DeepEqual(b)
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
