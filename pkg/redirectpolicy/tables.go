// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

const (
	LRPTableName = "localredirectpolicies"
)

var (
	lrpIDIndex = statedb.Index[*LRPConfig, k8s.ServiceID]{
		Name: "id",
		FromObject: func(obj *LRPConfig) index.KeySet {
			// FIXME: Figure out which type to use for k8s object names. NamespacedName?
			return index.NewKeySet(index.String(obj.ID.String()))
		},
		FromKey: index.Stringer[k8s.ServiceID],
		Unique:  true,
	}

	lrpServiceIndex = statedb.Index[*LRPConfig, k8s.ServiceID]{
		Name: "service",
		FromObject: func(lrp *LRPConfig) index.KeySet {
			if lrp.ServiceID == nil {
				return index.KeySet{}
			}
			return index.NewKeySet(index.String(lrp.ServiceID.String()))
		},
		FromKey: index.Stringer[k8s.ServiceID],
		Unique:  false,
	}

	lrpAddressIndex = statedb.Index[*LRPConfig, lb.L3n4Addr]{
		Name: "address",
		FromObject: func(lrp *LRPConfig) index.KeySet {
			if lrp.LRPType != lrpConfigTypeAddr {
				return index.KeySet{}
			}
			keys := make([]index.Key, 0, len(lrp.FrontendMappings))
			for _, feM := range lrp.FrontendMappings {
				keys = append(keys, feM.FEAddr.Bytes())

			}
			return index.NewKeySet(keys...)
		},
		FromKey: func(addr lb.L3n4Addr) index.Key { return addr.Bytes() },
		Unique:  false,
	}
)

func NewLRPTable(db *statedb.DB) (statedb.RWTable[*LRPConfig], error) {
	tbl, err := statedb.NewTable(
		LRPTableName,
		lrpIDIndex,
		lrpServiceIndex,
		lrpAddressIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

const (
	PodTableName = "k8s-pods"
)

var (
	PodUIDIndex = statedb.Index[LocalPod, types.UID]{
		Name: "uid",
		FromObject: func(obj LocalPod) index.KeySet {
			return index.NewKeySet(index.String(string(obj.UID)))
		},
		FromKey: func(uid types.UID) index.Key { return index.String(string(uid)) },
		Unique:  true,
	}
	PodNameIndex = statedb.Index[LocalPod, string]{
		Name: "name",
		FromObject: func(obj LocalPod) index.KeySet {
			return index.NewKeySet(index.String(obj.Namespace + "/" + obj.Name))
		},
		FromKey: index.String,
		Unique:  true,
	}
)

type podAddr struct {
	lb.L3n4Addr
	portName string
}

type LocalPod struct {
	*slim_corev1.Pod

	L3n4Addrs []podAddr
	LabelSet  labels.Set
}

func NewPodTable(db *statedb.DB) (statedb.RWTable[LocalPod], error) {
	tbl, err := statedb.NewTable(
		PodTableName,
		PodUIDIndex,
		PodNameIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

type lrpListerWatcher cache.ListerWatcher

func newLRPListerWatcher(cs client.Clientset) lrpListerWatcher {
	if !cs.IsEnabled() {
		return nil
	}
	return k8sUtils.ListerWatcherFromTyped(cs.CiliumV2().CiliumLocalRedirectPolicies("" /* all namespaces */))
}

func registerLRPReflector(enabled lrpIsEnabled, db *statedb.DB, jg job.Group, lw lrpListerWatcher, lrps statedb.RWTable[*LRPConfig]) {
	if !enabled || lw == nil {
		return
	}

	k8s.RegisterReflector(jg, db,
		k8s.ReflectorConfig[*LRPConfig]{
			Name:          "lrps",
			Table:         lrps,
			ListerWatcher: lw,
			Transform: func(obj any) (*LRPConfig, bool) {
				clrp, ok := obj.(*ciliumv2.CiliumLocalRedirectPolicy)
				if !ok {
					return nil, false
				}
				rp, err := Parse(clrp, true)
				return rp, err == nil
			},
		})
}

type podListerWatcher cache.ListerWatcher

func newPodListerWatcher(cs client.Clientset) podListerWatcher {
	if !cs.IsEnabled() {
		return nil
	}
	return k8sUtils.ListerWatcherWithModifiers(
		k8sUtils.ListerWatcherFromTyped(cs.Slim().CoreV1().Pods("")),
		func(opts *metav1.ListOptions) {
			opts.FieldSelector = fields.ParseSelectorOrDie("spec.nodeName=" + nodeTypes.GetName()).String()
		})
}

func podReflectorConfig(db *statedb.DB, jg job.Group, lw podListerWatcher, pods statedb.RWTable[LocalPod]) k8s.ReflectorConfig[LocalPod] {
	return k8s.ReflectorConfig[LocalPod]{
		Name:          "pods",
		Table:         pods,
		ListerWatcher: lw,
		Transform: func(obj any) (LocalPod, bool) {
			pod, ok := obj.(*slim_corev1.Pod)
			if !ok {
				return LocalPod{}, false
			}
			return LocalPod{
				Pod:       pod,
				LabelSet:  labels.Set(pod.GetLabels()),
				L3n4Addrs: podAddrs(pod),
			}, true
		},
	}
}
