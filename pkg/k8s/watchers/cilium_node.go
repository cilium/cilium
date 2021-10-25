// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2020 Authors of Cilium

package watchers

import (
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) ciliumNodeInit(ciliumNPClient *k8s.K8sCiliumClient) {
	ciliumNodeStore, ciliumNodeInformer := informer.NewInformer(
		cache.NewListWatchFromClient(ciliumNPClient.CiliumV2().RESTClient(),
			cilium_v2.CNPluralName, v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumNode{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCiliumNode, metricCreate, valid, equal) }()
				if ciliumNode := k8s.ObjToCiliumNode(obj); ciliumNode != nil {
					valid = true
					n := nodeTypes.ParseCiliumNode(ciliumNode)
					if n.IsLocal() {
						return
					}
					k.nodeDiscoverManager.NodeUpdated(n)
					k.K8sEventProcessed(metricCiliumNode, metricCreate, true)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCiliumNode, metricUpdate, valid, equal) }()
				if oldCN := k8s.ObjToCiliumNode(oldObj); oldCN != nil {
					if ciliumNode := k8s.ObjToCiliumNode(newObj); ciliumNode != nil {
						valid = true
						if oldCN.DeepEqual(ciliumNode) {
							equal = true
							return
						}
						n := nodeTypes.ParseCiliumNode(ciliumNode)
						if n.IsLocal() {
							return
						}
						k.nodeDiscoverManager.NodeUpdated(n)
						k.K8sEventProcessed(metricCiliumNode, metricUpdate, true)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				var valid, equal bool
				defer func() { k.K8sEventReceived(metricCiliumNode, metricDelete, valid, equal) }()
				ciliumNode := k8s.ObjToCiliumNode(obj)
				if ciliumNode == nil {
					return
				}
				valid = true
				n := nodeTypes.ParseCiliumNode(ciliumNode)
				k.nodeDiscoverManager.NodeDeleted(n)
			},
		},
		k8s.ConvertToCiliumNode,
	)

	k.ciliumNodeStore = ciliumNodeStore

	k.blockWaitGroupToSyncResources(wait.NeverStop, nil, ciliumNodeInformer.HasSynced, k8sAPIGroupCiliumNodeV2)
	go ciliumNodeInformer.Run(wait.NeverStop)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumNodeV2)
}
