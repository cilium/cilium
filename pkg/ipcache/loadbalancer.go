// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/annotation"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
)

type loadBalancerFrontendWatcher struct {
	log           *slog.Logger
	ipcache       *IPCache
	db            *statedb.DB
	frontends     statedb.Table[*loadbalancer.Frontend]
	dropByDefault bool
}

type LoadBalancerFrontendWatcherParams struct {
	cell.In

	Log       *slog.Logger
	IPCache   *IPCache
	DB        *statedb.DB
	Frontends statedb.Table[*loadbalancer.Frontend]
	LBConfig  loadbalancer.Config
}

func NewLoadBalancerFrontendWatcher(params LoadBalancerFrontendWatcherParams) loadBalancerFrontendWatcher {
	return loadBalancerFrontendWatcher{
		log:           params.Log,
		ipcache:       params.IPCache,
		db:            params.DB,
		frontends:     params.Frontends,
		dropByDefault: params.LBConfig.LBUnsupportedProtoAction == loadbalancer.LBUnsupportedProtoActionDrop,
	}
}

func RegisterLoadBalanceFrontendWatcher(watcher loadBalancerFrontendWatcher, jobGroup job.Group) error {
	jobGroup.Add(job.Observer(
		"loadbalancer-frontend-watcher",
		watcher.onFrontendChange,
		statedb.Observable(watcher.db, watcher.frontends),
	))
	return nil
}

// isCandidateUnroutable() returns true if a [loadbalancer.Frontend] is a candidate
// to parent an IPCache entry with FlagUnroutable set.
func (watcher loadBalancerFrontendWatcher) isCandidateUnroutable(fe *loadbalancer.Frontend) bool {
	if fe.Address.AddrCluster().IsUnspecified() {
		return false
	}

	switch fe.Type {
	case loadbalancer.SVCTypeLoadBalancer,
		loadbalancer.SVCTypeClusterIP,
		loadbalancer.SVCTypeExternalIPs:
		return fe.Address.Scope() == loadbalancer.ScopeExternal
	}

	return false
}

// useUnroutableFlag() returns true if the underlying Service of a Frontend has
// UnsupportedProtoAction=drop. If this is unspecified, this returns the default
// action from the watcher.
func (watcher loadBalancerFrontendWatcher) useUnroutableFlag(fe *loadbalancer.Frontend) bool {
	switch fe.Service.UnsupportedProtoAction {
	case annotation.UnsupportedProtoActionForward:
		return false
	case annotation.UnsupportedProtoActionDrop:
		return true
	}

	// Service does not express an action, so use the default setting
	return watcher.dropByDefault
}

func (watcher loadBalancerFrontendWatcher) onFrontendChange(
	ctx context.Context,
	change statedb.Change[*loadbalancer.Frontend],
) error {
	fe := change.Object
	if !watcher.isCandidateUnroutable(fe) {
		return nil
	}

	// Compute the resource ID that uniquely identifies the references
	// between this FE and the underlying IPCache entry. Note these are
	// in a specific format, delimited by a forward-slash, so we delimit
	// the FE L3n4Addr with a colon instead.
	resourceID := ipcacheTypes.NewResourceID(
		ipcacheTypes.ResourceKindService,
		fe.Service.Name.Namespace(),
		fe.Address.StringWithProtocolDelimited(":"),
	)

	flags := ipcacheTypes.EndpointFlags{}
	if watcher.useUnroutableFlag(fe) {
		flags.SetUnroutable(true)
	}

	addr := fe.Address.AddrCluster()
	labels := make(labels.Labels, 1)
	labels.AddWorldLabel(addr.Addr())

	if change.Deleted || !flags.IsValid() {
		watcher.ipcache.RemoveMetadata(
			addr.AsPrefixCluster(),
			resourceID,
			labels,
			ipcacheTypes.EndpointFlags{},
		)
	} else {
		watcher.ipcache.UpsertMetadata(
			addr.AsPrefixCluster(),
			source.Generated,
			resourceID,
			labels,
			flags,
		)
	}

	return nil
}
