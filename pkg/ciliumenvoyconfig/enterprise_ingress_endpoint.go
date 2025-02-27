// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/promise"
	"github.com/cilium/cilium/pkg/proxy"
)

const (
	ingressEndpointNameLabel = "ingress.cilium.io/name"
)

type ingressEndpointParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group

	OwnerPromise            promise.Promise[regeneration.Owner]
	PolicyRepositoryPromise promise.Promise[endpoint.PolicyRepoGetter]
	EndpointManager         endpointmanager.EndpointManager
	IPCache                 *ipcache.IPCache
	Proxy                   *proxy.Proxy
	Allocator               cache.IdentityAllocator
	CTMapGC                 ctmap.GCRunner
}

type ingressEndpointManager struct {
	logger *slog.Logger

	mutex                   sync.Mutex
	ownerPromise            promise.Promise[regeneration.Owner]
	policyRepositoryPromise promise.Promise[endpoint.PolicyRepoGetter]

	owner            regeneration.Owner
	policyRepository endpoint.PolicyRepoGetter
	endpointManager  endpointmanager.EndpointManager
	ipCache          *ipcache.IPCache
	proxy            *proxy.Proxy
	allocator        cache.IdentityAllocator
	ctMapGC          ctmap.GCRunner
}

func newIngressEndpointManager(params ingressEndpointParams) *ingressEndpointManager {
	res := &ingressEndpointManager{
		logger: params.Logger,

		ownerPromise:            params.OwnerPromise,
		policyRepositoryPromise: params.PolicyRepositoryPromise,

		endpointManager: params.EndpointManager,
		ipCache:         params.IPCache,
		proxy:           params.Proxy,
		allocator:       params.Allocator,
		ctMapGC:         params.CTMapGC,
	}
	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			//go func() {
			//	res.mutex.Lock()
			//	defer res.mutex.Unlock()
			//
			//	params.Logger.Debug("TAM waiting for daemon in job")
			//	owner, _ := res.ownerPromise.Await(context.Background())
			//	res.owner = owner
			//
			//	p, _ := res.policyRepositoryPromise.Await(context.Background())
			//	res.policyRepository = p
			//	params.Logger.Debug("TAM done waiting for daemon in job")
			//}()
			return nil
		},
	})

	params.JobGroup.Add(job.OneShot("wait-for-daemon", func(ctx context.Context, health cell.Health) error {
		res.mutex.Lock()
		defer res.mutex.Unlock()

		params.Logger.Debug("TAM waiting for daemon in job")
		owner, err := res.ownerPromise.Await(context.Background())
		if err != nil {
			return fmt.Errorf("TAM failed to wait for daemon: %w", err)
		}
		res.owner = owner

		p, err := res.policyRepositoryPromise.Await(context.Background())
		if err != nil {
			return fmt.Errorf("TAM failed to wait for daemon: %w", err)
		}
		res.policyRepository = p
		params.Logger.Debug("TAM done waiting for daemon in job")

		return nil
	}))

	return res
}

func (m *ingressEndpointManager) ready(ctx context.Context) bool {
	return m.owner != nil && m.policyRepository != nil
}

func (m *ingressEndpointManager) ensureIngressEndpoint(ctx context.Context, name string, lbs labels.Labels) (*endpoint.Endpoint, error) {
	if !m.ready(ctx) {
		return nil, fmt.Errorf("deamon sub-system is not ready")
	}

	nameLabel := labels.Labels{
		ingressEndpointNameLabel: labels.NewLabel(ingressEndpointNameLabel, name, labels.LabelSourceK8s),
	}

	// Check if the existing endpoint is already present
	ep := m.endpointManager.GetIngressEndpoint(nameLabel)
	m.logger.Info("TAM debugging", logfields.Endpoint, ep)
	if ep != nil {
		lbs.MergeLabels(nameLabel)
		ep.InitWithIngressLabels(ctx, endpointmanager.LaunchTime, lbs)
		return ep, nil
	}

	ep, err := endpoint.CreateIngressEndpoint(m.owner, m.policyRepository, m.ipCache, m.proxy, m.allocator, m.ctMapGC)
	if err != nil {
		return nil, err
	}

	if err = m.endpointManager.AddEndpoint(m.owner, ep); err != nil {
		return nil, err
	}

	lbs.MergeLabels(nameLabel)
	ep.InitWithIngressLabels(ctx, endpointmanager.LaunchTime, lbs)

	return nil, nil
}
