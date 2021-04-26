//  Copyright 2021 Authors of Cilium
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

package watchers

import (
	"net"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

func (k *K8sWatcher) ciliumEndpointBatchInit(client *k8s.K8sCiliumClient) {

	log.Debug("Initializing CEB controller")
	_, cebController := informer.NewInformer(
		cache.NewListWatchFromClient(client.CiliumV2().RESTClient(),
			cilium_v2.CEBPluralName, v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumEndpointBatch{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if ceb := k8s.ObjToCiliumEndpointBatch(obj); ceb != nil {
					k.endpointBatchAdded(ceb)
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldCeb := k8s.ObjToCiliumEndpointBatch(oldObj); oldCeb != nil {
					if newCeb := k8s.ObjToCiliumEndpointBatch(newObj); newCeb != nil {
						if oldCeb.DeepEqual(newCeb) {
							return
						}
						k.endpointBatchUpdated(oldCeb, newCeb)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				if ceb := k8s.ObjToCiliumEndpointBatch(obj); ceb != nil {
					k.endpointBatchDeleted(ceb)
				}
			},
		},
		nil,
	)
	k.blockWaitGroupToSyncResources(
		wait.NeverStop,
		nil,
		cebController.HasSynced,
		k8sAPIGroupCiliumEndpointBatchV2,
	)

	go cebController.Run(wait.NeverStop)
}

func (k *K8sWatcher) endpointBatchAdded(ceb *cilium_v2.CiliumEndpointBatch) {
	for i, ep := range ceb.Endpoints {
		log.WithFields(logrus.Fields{
			"EPBatchName":      ceb.GetName(),
			"CoreEndpointName": ep.Name,
		}).Debug("New CEB added, Calling CoreEndpointUpdate")
		k.coreEndpointUpdate(&ceb.Endpoints[i])
	}
}

func (k *K8sWatcher) endpointBatchUpdated(oldCeb, newCeb *cilium_v2.CiliumEndpointBatch) {
	oldCeps := make(map[string]*cilium_v2.CoreCiliumEndpoint)
	for i, ep := range oldCeb.Endpoints {
		// TODO change to debug
		log.WithFields(logrus.Fields{
			"EPBatchName":      oldCeb.GetName(),
			"CoreEndpointName": ep.Name,
		}).Debug("EndpointBatch update with old CEB")
		oldCeps[ep.Name] = &oldCeb.Endpoints[i]
	}

	newCeps := make(map[string]*cilium_v2.CoreCiliumEndpoint)
	for i, ep := range newCeb.Endpoints {
		// TODO change to debug
		log.WithFields(logrus.Fields{
			"EPBatchName":      newCeb.GetName(),
			"CoreEndpointName": ep.Name,
		}).Debug("EndpointBatch update with new CEB")
		newCeps[ep.Name] = &newCeb.Endpoints[i]
	}
	// Process if any new items added into newCeb
	for epName, newEp := range newCeps {
		if _, ok := oldCeps[epName]; !ok {
			log.WithField("CEP name", epName).Debugf("New CEP added in :%s, calling coreEndpointUpdate", newCeb.GetName())
			k.coreEndpointUpdate(newEp)
		}
	}
	// process removed entries from ceb. old ceb would have one or more stale cep
	// entries. new ceb is source of truth.
	for epName, oldEp := range oldCeps {
		if _, ok := newCeps[epName]; !ok {
			log.WithField("CEP name", epName).Debugf("CEP removed in :%s, calling coreEndpointDelete", newCeb.GetName())
			k.coreEndpointDelete(oldEp)
		}
	}

	// process if any cep entries get changed from old to new
	for epName, newCep := range newCeps {
		if oldCep, ok := oldCeps[epName]; ok {
			if !oldCep.DeepEqual(newCep) {
				log.WithField("CEP name", epName).Debug("CEP modified in :%s, calling coreEndpointUpdate", newCeb.GetName())
				k.coreEndpointUpdate(newCep)
			}
		}
	}
}

func (k *K8sWatcher) endpointBatchDeleted(ceb *cilium_v2.CiliumEndpointBatch) {
	log.Debugf("CEB deleted called  ", ceb.GetName())
	for _, ep := range ceb.Endpoints {
		log.WithFields(logrus.Fields{
			"EPBatchName":      ceb.GetName(),
			"CoreEndpointName": ep.Name,
		}).Debug("CEB deleted, Calling CoreEndpointDelete")
		k.coreEndpointDelete(&ep)
	}
}

func (k *K8sWatcher) coreEndpointUpdate(endpoint *cilium_v2.CoreCiliumEndpoint) {
	/*
		for _, ep := range k.endpointManager.GetEndpoints() {
			if ep.GetK8sPodName() == endpoint.Name {
				fmt.Println("Skip Processing local Endpoints")
				return
			}
		}*/
	// default to the standard key
	// TODO skip local processing local endpoints
	encryptionKey := node.GetIPsecKeyIdentity()

	id := identity.NumericIdentity(endpoint.IdentityID)

	encryptionKey = uint8(endpoint.Encryption.Key)

	if endpoint.Networking != nil {
		if endpoint.Networking.NodeIP == "" {
			// When upgrading from an older version, the nodeIP may
			// not be available yet in the CiliumEndpoint and we
			// have to wait for it to be propagated
			return
		}

		nodeIP := net.ParseIP(endpoint.Networking.NodeIP)
		if nodeIP == nil {
			log.WithField("nodeIP", endpoint.Networking.NodeIP).Warning("Unable to parse node IP while processing CiliumEndpoint update")
			return
		}

		k8sMeta := &ipcache.K8sMetadata{
			Namespace:  endpoint.Namespace,
			PodName:    endpoint.Name,
			NamedPorts: make(policy.NamedPortMap, len(endpoint.NamedPorts)),
		}
		for _, port := range endpoint.NamedPorts {
			p, err := u8proto.ParseProtocol(port.Protocol)
			if err != nil {
				continue
			}
			k8sMeta.NamedPorts[port.Name] = policy.PortProto{
				Port:  uint16(port.Port),
				Proto: uint8(p),
			}
		}

		namedPortsChanged := false
		for _, pair := range endpoint.Networking.Addressing {
			if pair.IPV4 != "" {
				_, portsChanged := ipcache.IPIdentityCache.Upsert(pair.IPV4, nodeIP, encryptionKey, k8sMeta,
					ipcache.Identity{ID: id, Source: source.CustomResource})
				if portsChanged {
					namedPortsChanged = true
				}
			}

			if pair.IPV6 != "" {
				_, portsChanged := ipcache.IPIdentityCache.Upsert(pair.IPV6, nodeIP, encryptionKey, k8sMeta,
					ipcache.Identity{ID: id, Source: source.CustomResource})
				if portsChanged {
					namedPortsChanged = true
				}
			}
		}
		if namedPortsChanged {
			k.policyManager.TriggerPolicyUpdates(true, "Named ports added or updated")
		}
	}
}

func (k *K8sWatcher) coreEndpointDelete(endpoint *cilium_v2.CoreCiliumEndpoint) {
	/*
		for _, ep := range k.endpointManager.GetEndpoints() {
			if ep.GetK8sPodName() == endpoint.Name {
				fmt.Println("Skip Processing local Endpoint")
				return
			}
		}*/
	if endpoint.Networking != nil {
		namedPortsChanged := false
		for _, pair := range endpoint.Networking.Addressing {
			if pair.IPV4 != "" {
				portsChanged := ipcache.IPIdentityCache.Delete(pair.IPV4, source.CustomResource)
				if portsChanged {
					namedPortsChanged = true
				}
			}

			if pair.IPV6 != "" {
				portsChanged := ipcache.IPIdentityCache.Delete(pair.IPV6, source.CustomResource)
				if portsChanged {
					namedPortsChanged = true
				}
			}
		}
		if namedPortsChanged {
			k.policyManager.TriggerPolicyUpdates(true, "Named ports deleted")
		}
	}
}
