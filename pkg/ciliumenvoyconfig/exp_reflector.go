// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"iter"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/part"
	"github.com/cilium/statedb/reconciler"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

// Types for the ListerWatchers of the CEC resources. Abstracted so that tests can
// inject custom ones.
type (
	cecListerWatcher  cache.ListerWatcher
	ccecListerWatcher cache.ListerWatcher

	listerWatchers struct {
		cec  cecListerWatcher
		ccec ccecListerWatcher
	}
)

func cecListerWatchers(cs client.Clientset) (out struct {
	cell.Out
	LW listerWatchers
}) {
	if cs.IsEnabled() {
		out.LW.cec = utils.ListerWatcherFromTyped(cs.CiliumV2().CiliumEnvoyConfigs(""))
		out.LW.ccec = utils.ListerWatcherFromTyped(cs.CiliumV2().CiliumClusterwideEnvoyConfigs())
	}
	return
}

type nodeLabels struct {
	atomic.Pointer[map[string]string]
}

func registerCECReflector(
	ecfg experimental.Config,
	p *cecResourceParser,
	crdSync promise.Promise[synced.CRDSync],
	nodeLabels *nodeLabels,
	log *slog.Logger,
	lws listerWatchers,
	g job.Group,
	db *statedb.DB,
	tbl statedb.RWTable[*CEC],
	frontends statedb.Table[*experimental.Frontend],
) error {
	if lws.cec == nil || !ecfg.EnableExperimentalLB {
		return nil
	}
	transform := func(txn statedb.ReadTxn, obj any) (*CEC, bool) {
		var (
			objMeta *metav1.ObjectMeta
			spec    *ciliumv2.CiliumEnvoyConfigSpec
		)

		switch cecObj := obj.(type) {
		case *ciliumv2.CiliumEnvoyConfig:
			objMeta = &cecObj.ObjectMeta
			spec = &cecObj.Spec
		case *ciliumv2.CiliumClusterwideEnvoyConfig:
			objMeta = &cecObj.ObjectMeta
			spec = &cecObj.Spec
		}

		selectsLocalNode := true
		selector := labels.Everything()
		if spec.NodeSelector != nil {
			var err error
			selector, err = slim_metav1.LabelSelectorAsSelector(spec.NodeSelector)
			if err != nil {
				log.Warn("Skipping CiliumEnvoyConfig due to invalid NodeSelector",
					"namespace", objMeta.GetNamespace(),
					"name", objMeta.GetName(),
					logfields.Error, err)
				return nil, false
			}
			selectsLocalNode = selector.Matches(labels.Set(*nodeLabels.Load()))
		}

		resources, err := p.parseResources(
			objMeta.GetNamespace(),
			objMeta.GetName(),
			spec.Resources,
			len(spec.Services) > 0,
			useOriginalSourceAddress(objMeta),
			true,
		)
		if err != nil {
			log.Warn("Skipping CiliumEnvoyConfig due to malformed xDS resources",
				"namespace", objMeta.GetNamespace(),
				"name", objMeta.GetName(),
				logfields.Error, err)
			return nil, false
		}

		var listeners part.Map[string, uint16]
		for _, l := range resources.Listeners {
			var proxyPort uint16
			if addr := l.GetAddress(); addr != nil {
				if sa := addr.GetSocketAddress(); sa != nil {
					proxyPort = uint16(sa.GetPortValue())
					listeners = listeners.Set(l.Name, proxyPort)
				}
			}
		}

		cec := &CEC{
			Name: k8sTypes.NamespacedName{
				Name:      objMeta.GetName(),
				Namespace: objMeta.GetNamespace(),
			},
			Selector:         selector,
			SelectsLocalNode: selectsLocalNode,
			Spec:             spec,
			Resources:        resources,
			Listeners:        listeners,
			Status:           reconciler.StatusPending(),
		}

		// Fill in the endpoints
		updateBackends(cec, txn, frontends)

		return cec, true
	}

	// CiliumEnvoyConfig reflection
	err := k8s.RegisterReflector(
		g,
		db,
		k8s.ReflectorConfig[*CEC]{
			Name:          "cec",
			Table:         tbl,
			ListerWatcher: lws.cec,
			Transform:     transform,
			QueryAll: func(txn statedb.ReadTxn, tbl statedb.Table[*CEC]) iter.Seq2[*CEC, statedb.Revision] {
				return statedb.Filter(
					tbl.All(txn),
					func(cec *CEC) bool { return cec.Name.Namespace != "" },
				)
			},
			CRDSync: crdSync,
		},
	)
	if err != nil {
		return err
	}

	// CiliumClusterwideEnvoyConfig reflection
	return k8s.RegisterReflector(
		g,
		db,
		k8s.ReflectorConfig[*CEC]{
			Name:          "ccec",
			Table:         tbl,
			ListerWatcher: lws.ccec,
			Transform:     transform,
			QueryAll: func(txn statedb.ReadTxn, tbl statedb.Table[*CEC]) iter.Seq2[*CEC, statedb.Revision] {
				return statedb.Filter(
					tbl.All(txn),
					func(cec *CEC) bool { return cec.Name.Namespace == "" },
				)
			},
			CRDSync: crdSync,
		},
	)
}
