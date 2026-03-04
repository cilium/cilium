// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nullroute

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/annotation"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
)

type metadataMutator interface {
	UpsertMetadata(prefix cmtypes.PrefixCluster, src source.Source, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata)
	RemoveMetadata(prefix cmtypes.PrefixCluster, resource ipcacheTypes.ResourceID, aux ...ipcache.IPMetadata)
}

// Assert the production IPCache still satisfies the narrow seam this package
// depends on. This makes interface drift fail at compile time instead of only
// surfacing later in Hive wiring or tests.
var _ metadataMutator = (*ipcache.IPCache)(nil)

type loadBalancerFrontendWatcher struct {
	metadata             metadataMutator
	db                   *statedb.DB
	frontends            statedb.Table[*loadbalancer.Frontend]
	dropByDefault        bool
	defaultLBServiceIPAM string
}

type loadBalancerFrontendWatcherParams struct {
	cell.In

	IPCache   *ipcache.IPCache
	DB        *statedb.DB
	Frontends statedb.Table[*loadbalancer.Frontend]
	LBConfig  loadbalancer.Config
	ExtConfig loadbalancer.ExternalConfig
}

func newLoadBalancerFrontendWatcher(params loadBalancerFrontendWatcherParams) loadBalancerFrontendWatcher {
	return loadBalancerFrontendWatcher{
		metadata:             params.IPCache,
		db:                   params.DB,
		frontends:            params.Frontends,
		dropByDefault:        params.LBConfig.LBUnsupportedProtoAction == loadbalancer.LBUnsupportedProtoActionDrop,
		defaultLBServiceIPAM: params.ExtConfig.DefaultLBServiceIPAM,
	}
}

func registerLoadBalancerFrontendWatcher(watcher loadBalancerFrontendWatcher, jobGroup job.Group) error {
	jobGroup.Add(job.Observer(
		"nullroute-loadbalancer-frontend-watcher",
		watcher.onFrontendChange,
		statedb.Observable(watcher.db, watcher.frontends),
	))
	return nil
}

// isNullRouteCandidate() returns true if a [loadbalancer.Frontend] is a candidate
// to parent an IPCache entry with FlagNullRoute set.
func (watcher loadBalancerFrontendWatcher) isNullRouteCandidate(fe *loadbalancer.Frontend) bool {
	if fe.Address.AddrCluster().IsUnspecified() {
		return false
	}

	switch fe.Type {
	case loadbalancer.SVCTypeLoadBalancer,
		loadbalancer.SVCTypeClusterIP:
		// Only external scoped entries can parent null route entries.
		if fe.Address.Scope() != loadbalancer.ScopeExternal {
			return false
		}

		// We only want to reconcile null route entries if LB-IPAM has allocated
		// the VIP, otherwise we risk reconciling Node internal IPs into IPCache
		// and causing connectivity faults.
		lbClass := fe.Service.LoadBalancerClass
		if lbClass == nil {
			return watcher.defaultLBServiceIPAM == lbipamconfig.DefaultLBClassLBIPAM
		}

		// The service has a loadBalancerClass, so we only include a null route
		// entry if it's a class Cilium actively manages, again to avoid
		// reconciling null route entries for IP addresses we don't manage.
		//
		// TODO: improve this in future, perhaps by matching against known
		// CiliumInternalIPs.
		return *lbClass == cilium_api_v2alpha1.BGPLoadBalancerClass ||
			*lbClass == cilium_api_v2alpha1.L2AnnounceLoadBalancerClass

	case loadbalancer.SVCTypeExternalIPs:
		// ExternalIPs are provided by cluster admins, rather than being allocated
		// by an IPAM, so the loadBalancerClass and default LB-IPAM checks above do
		// not apply.
		return fe.Address.Scope() == loadbalancer.ScopeExternal
	}

	return false
}

// useNullRouteFlag() returns true if the underlying Service of a Frontend has
// UnsupportedProtoAction=drop. If this is unspecified, this returns the default
// action from the watcher.
func (watcher loadBalancerFrontendWatcher) useNullRouteFlag(fe *loadbalancer.Frontend) bool {
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
	if !watcher.isNullRouteCandidate(fe) {
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
	if watcher.useNullRouteFlag(fe) {
		flags.SetNullRoute(true)
	}

	addr := fe.Address.AddrCluster()
	labels := make(labels.Labels, 1)
	labels.AddWorldLabel(addr.Addr())

	if change.Deleted || !flags.IsValid() {
		watcher.metadata.RemoveMetadata(
			addr.AsPrefixCluster(),
			resourceID,
			labels,
			ipcacheTypes.EndpointFlags{},
		)
	} else {
		watcher.metadata.UpsertMetadata(
			addr.AsPrefixCluster(),
			source.Generated,
			resourceID,
			labels,
			flags,
		)
	}

	return nil
}
