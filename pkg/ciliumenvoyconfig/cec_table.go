// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumenvoyconfig

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/part"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/experimental"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/promise"
)

type CEC struct {
	Name      k8sTypes.NamespacedName
	Spec      *ciliumv2.CiliumEnvoyConfigSpec
	Resources envoy.Resources `json:"-"`
	Listeners part.Map[string, uint16]
}

func (*CEC) TableHeader() []string {
	return []string{
		"Name",
		"NodeSelector",
		"Services",
		"BackendServices",
		"Listeners",
	}
}

func (cec *CEC) TableRow() []string {
	var services, beServices, listeners []string
	for _, svcl := range cec.Spec.Services {
		services = append(services, svcl.Namespace+"/"+svcl.Name)
	}
	for _, svcl := range cec.Spec.BackendServices {
		beServices = append(beServices, svcl.Namespace+"/"+svcl.Name)
	}
	iter := cec.Listeners.All()
	for name, port, ok := iter.Next(); ok; name, port, ok = iter.Next() {
		listeners = append(listeners, fmt.Sprintf("%s:%d", name, port))
	}
	return []string{
		cec.Name.String(),
		cec.Spec.NodeSelector.String(),
		strings.Join(services, ", "),
		strings.Join(beServices, ", "),
		strings.Join(listeners, ", "),
	}
}

var (
	CECTableName = "ciliumenvoyconfigs"

	cecNameIndex = statedb.Index[*CEC, k8sTypes.NamespacedName]{
		Name: "name",
		FromObject: func(obj *CEC) index.KeySet {
			return index.NewKeySet(index.String(obj.Name.String()))
		},
		FromKey: index.Stringer[k8sTypes.NamespacedName],
		Unique:  true,
	}

	cecByName = cecNameIndex.Query

	cecServiceIndex = statedb.Index[*CEC, loadbalancer.ServiceName]{
		Name: "service",
		FromObject: func(obj *CEC) index.KeySet {
			keys := make([]index.Key, len(obj.Spec.Services))
			for i, svcl := range obj.Spec.Services {
				keys[i] = index.String(
					loadbalancer.ServiceName{
						Namespace: svcl.Namespace,
						Name:      svcl.Name,
					}.String(),
				)
			}
			return index.NewKeySet(keys...)
		},
		FromKey: func(key loadbalancer.ServiceName) index.Key {
			return index.String(key.String())
		},
		Unique: false,
	}

	cecByServiceName = cecServiceIndex.Query
)

func newCECTable(db *statedb.DB) (statedb.RWTable[*CEC], error) {
	tbl, err := statedb.NewTable(
		CECTableName,
		cecNameIndex,
		cecServiceIndex,
	)
	if err != nil {
		return nil, err
	}
	return tbl, db.RegisterTable(tbl)
}

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

func registerCECReflector(
	ecfg experimental.Config,
	p *cecResourceParser,
	crdSync promise.Promise[synced.CRDSync],
	log *slog.Logger,
	lws listerWatchers,
	g job.Group,
	db *statedb.DB,
	tbl statedb.RWTable[*CEC],
) error {
	if lws.cec == nil || !ecfg.EnableExperimentalLB {
		return nil
	}
	transform := func(obj any) (*CEC, bool) {
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
		return &CEC{
			Name: k8sTypes.NamespacedName{
				Name:      objMeta.GetName(),
				Namespace: objMeta.GetNamespace(),
			},
			Spec:      spec,
			Resources: resources,
			Listeners: listeners,
		}, true
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
			QueryAll: func(txn statedb.ReadTxn, tbl statedb.Table[*CEC]) statedb.Iterator[*CEC] {
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
			QueryAll: func(txn statedb.ReadTxn, tbl statedb.Table[*CEC]) statedb.Iterator[*CEC] {
				return statedb.Filter(
					tbl.All(txn),
					func(cec *CEC) bool { return cec.Name.Namespace == "" },
				)
			},
			CRDSync: crdSync,
		},
	)
}
