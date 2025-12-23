// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gatewayl4

import (
	"context"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	ciliumScheme "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned/scheme"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/promise"
)

// Types for the ListerWatchers of the Gateway L4 config resources.
type (
	gatewayL4ListerWatcher cache.ListerWatcher

	listerWatchers struct {
		gatewayL4 gatewayL4ListerWatcher
	}
)

func gatewayL4ListerWatchers(cs client.Clientset) (out struct {
	cell.Out
	LW listerWatchers
},
) {
	if cs.IsEnabled() {
		out.LW.gatewayL4 = newGatewayL4ConfigListerWatcher(cs)
	}
	return
}

const (
	k8sAPIGroupCiliumGatewayL4ConfigV2Alpha1 = "cilium/v2alpha1::CiliumGatewayL4Config"
)

// registerGatewayL4K8sReflector registers reflector to Table[GatewayL4Config]
// from CiliumGatewayL4Config.
func registerGatewayL4K8sReflector(
	crdSync promise.Promise[synced.CRDSync],
	apiGroups *synced.APIGroups,
	lws listerWatchers,
	g job.Group,
	db *statedb.DB,
	tbl statedb.RWTable[*GatewayL4Config],
) error {
	if lws.gatewayL4 == nil {
		return nil
	}

	apiGroups.AddAPI(k8sAPIGroupCiliumGatewayL4ConfigV2Alpha1)

	transform := func(_ statedb.ReadTxn, obj any) (*GatewayL4Config, bool) {
		cfg, ok := obj.(*ciliumv2alpha1.CiliumGatewayL4Config)
		if !ok {
			return nil, false
		}

		return &GatewayL4Config{
			Name: k8sTypes.NamespacedName{
				Name:      cfg.GetName(),
				Namespace: cfg.GetNamespace(),
			},
			Labels: cfg.Labels,
			Spec:   &cfg.Spec,
		}, true
	}

	return k8s.RegisterReflector(
		g,
		db,
		k8s.ReflectorConfig[*GatewayL4Config]{
			Name:          "gatewayl4",
			Table:         tbl,
			ListerWatcher: lws.gatewayL4,
			Transform:     transform,
			MetricScope:   "CiliumGatewayL4Config",
			CRDSync:       crdSync,
		},
	)
}

type gatewayL4ConfigListerWatcher struct {
	client rest.Interface
}

func newGatewayL4ConfigListerWatcher(cs client.Clientset) cache.ListerWatcher {
	return &gatewayL4ConfigListerWatcher{
		client: cs.CiliumV2alpha1().RESTClient(),
	}
}

func (lw *gatewayL4ConfigListerWatcher) List(opts metav1.ListOptions) (k8sRuntime.Object, error) {
	result := &ciliumv2alpha1.CiliumGatewayL4ConfigList{}
	err := lw.client.Get().
		Resource(ciliumv2alpha1.CGL4CPluralName).
		Namespace(metav1.NamespaceAll).
		VersionedParams(&opts, ciliumScheme.ParameterCodec).
		Do(context.Background()).
		Into(result)
	return result, err
}

func (lw *gatewayL4ConfigListerWatcher) Watch(opts metav1.ListOptions) (watch.Interface, error) {
	return lw.client.Get().
		Resource(ciliumv2alpha1.CGL4CPluralName).
		Namespace(metav1.NamespaceAll).
		VersionedParams(&opts, ciliumScheme.ParameterCodec).
		Watch(context.Background())
}
