// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"iter"
	"log/slog"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	LRPTableName = "localredirectpolicies"
)

var (
	lrpIDIndex = statedb.Index[*LocalRedirectPolicy, lb.ServiceName]{
		Name: "id",
		FromObject: func(obj *LocalRedirectPolicy) index.KeySet {
			return index.NewKeySet(index.String(obj.ID.String()))
		},
		FromKey: index.Stringer[lb.ServiceName],
		Unique:  true,
	}

	lrpServiceIndex = statedb.Index[*LocalRedirectPolicy, lb.ServiceName]{
		Name: "service",
		FromObject: func(lrp *LocalRedirectPolicy) index.KeySet {
			return index.NewKeySet(index.String(lrp.ServiceID.String()))
		},
		FromKey: index.Stringer[lb.ServiceName],
		Unique:  false,
	}

	lrpAddressIndex = statedb.Index[*LocalRedirectPolicy, lb.L3n4Addr]{
		Name: "address",
		FromObject: func(lrp *LocalRedirectPolicy) index.KeySet {
			if lrp.LRPType != lrpConfigTypeAddr {
				return index.KeySet{}
			}
			keys := make([]index.Key, 0, len(lrp.FrontendMappings))
			for _, feM := range lrp.FrontendMappings {
				keys = append(keys, feM.feAddr.Bytes())

			}
			return index.NewKeySet(keys...)
		},
		FromKey: func(addr lb.L3n4Addr) index.Key { return addr.Bytes() },
		Unique:  false,
	}
)

func NewLRPTable(db *statedb.DB) (statedb.RWTable[*LocalRedirectPolicy], error) {
	return statedb.NewTable(
		db,
		LRPTableName,
		lrpIDIndex,
		lrpServiceIndex,
		lrpAddressIndex,
	)
}

type lrpListerWatcher cache.ListerWatcher

func newLRPListerWatcher(cs client.Clientset) lrpListerWatcher {
	if !cs.IsEnabled() {
		return nil
	}
	return k8sUtils.ListerWatcherFromTyped(cs.CiliumV2().CiliumLocalRedirectPolicies("" /* all namespaces */))
}

func registerLRPReflector(enabled lrpIsEnabled, cfg Config, db *statedb.DB, log *slog.Logger, jg job.Group, lw lrpListerWatcher, lrps statedb.RWTable[*LocalRedirectPolicy]) {
	if !enabled || lw == nil {
		return
	}

	k8s.RegisterReflector(jg, db,
		k8s.ReflectorConfig[*LocalRedirectPolicy]{
			Name:          "lrps",
			Table:         lrps,
			ListerWatcher: lw,
			MetricScope:   "CiliumLocalRedirectPolicy",
			TransformMany: func(_ statedb.ReadTxn, deleted bool, obj any) (toInsert, toDelete iter.Seq[*LocalRedirectPolicy]) {
				clrp := obj.(*ciliumv2.CiliumLocalRedirectPolicy)
				rp, err := parseLRP(cfg, log, clrp)
				if err != nil {
					log.Warn("Rejecting malformed CiliumLocalRedirectPolicy",
						logfields.K8sNamespace, clrp.Namespace,
						logfields.Name, clrp.Name,
						logfields.Error, err)
					toDelete = func(yield func(*LocalRedirectPolicy) bool) {
						yield(&LocalRedirectPolicy{
							ID:  lb.NewServiceName(clrp.Namespace, clrp.Name),
							UID: clrp.UID,
						})
					}
				} else {
					it := func(yield func(*LocalRedirectPolicy) bool) {
						yield(rp)
					}
					if deleted {
						toDelete = it
					} else {
						toInsert = it
					}
				}
				return
			},
		})
}
