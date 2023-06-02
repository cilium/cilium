// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"fmt"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/k8s/watchers/resources"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func (k *K8sWatcher) ciliumEndpointsInit(ciliumNPClient client.Clientset, asyncControllers *sync.WaitGroup) {
	// CiliumEndpoint objects are used for ipcache discovery until the
	// key-value store is connected
	var once sync.Once
	apiGroup := k8sAPIGroupCiliumEndpointV2
	for {
		cepIndexer, ciliumEndpointInformer := informer.NewIndexerInformer(
			utils.ListerWatcherFromTyped[*cilium_v2.CiliumEndpointList](ciliumNPClient.CiliumV2().CiliumEndpoints("")),
			&cilium_v2.CiliumEndpoint{},
			0,
			cache.ResourceEventHandlerFuncs{
				AddFunc: func(obj interface{}) {
					var valid, equal bool
					defer func() {
						k.K8sEventReceived(apiGroup, metricCiliumEndpoint, resources.MetricCreate, valid, equal)
					}()
					if ciliumEndpoint, ok := obj.(*types.CiliumEndpoint); ok {
						valid = true
						k.endpointUpdated(nil, ciliumEndpoint)
						k.K8sEventProcessed(metricCiliumEndpoint, resources.MetricCreate, true)
					}
				},
				UpdateFunc: func(oldObj, newObj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(apiGroup, metricCiliumEndpoint, resources.MetricUpdate, valid, equal) }()
					if oldCE := k8s.ObjToCiliumEndpoint(oldObj); oldCE != nil {
						if newCE := k8s.ObjToCiliumEndpoint(newObj); newCE != nil {
							valid = true
							if oldCE.DeepEqual(newCE) {
								equal = true
								return
							}
							k.endpointUpdated(oldCE, newCE)
							k.K8sEventProcessed(metricCiliumEndpoint, resources.MetricUpdate, true)
						}
					}
				},
				DeleteFunc: func(obj interface{}) {
					var valid, equal bool
					defer func() { k.K8sEventReceived(apiGroup, metricCiliumEndpoint, resources.MetricDelete, valid, equal) }()
					ciliumEndpoint := k8s.ObjToCiliumEndpoint(obj)
					if ciliumEndpoint == nil {
						return
					}
					valid = true
					k.endpointDeleted(ciliumEndpoint)
				},
			},
			k8s.ConvertToCiliumEndpoint,
			cache.Indexers{
				"localNode": CreateCiliumEndpointLocalPodIndexFunc(),
			},
		)
		k.ciliumEndpointIndexerMU.Lock()
		k.ciliumEndpointIndexer = cepIndexer
		k.ciliumEndpointIndexerMU.Unlock()
		isConnected := make(chan struct{})
		// once isConnected is closed, it will stop waiting on caches to be
		// synchronized.
		k.blockWaitGroupToSyncResources(isConnected, nil, ciliumEndpointInformer.HasSynced, k8sAPIGroupCiliumEndpointV2)

		once.Do(func() {
			// Signalize that we have put node controller in the wait group
			// to sync resources.
			asyncControllers.Done()
		})
		k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumEndpointV2)
		go ciliumEndpointInformer.Run(isConnected)

		<-kvstore.Connected()
		close(isConnected)

		log.Info("Connected to key-value store, stopping CiliumEndpoint watcher")

		k.k8sAPIGroups.RemoveAPI(k8sAPIGroupCiliumEndpointV2)
		k.cancelWaitGroupToSyncResources(k8sAPIGroupCiliumEndpointV2)
		// Create a new node controller when we are disconnected with the
		// kvstore
		<-kvstore.Client().Disconnected()

		log.Info("Disconnected from key-value store, restarting CiliumEndpoint watcher")
	}
}

func (k *K8sWatcher) endpointUpdated(oldEndpoint, endpoint *types.CiliumEndpoint) {
	var namedPortsChanged bool
	defer func() {
		if namedPortsChanged {
			k.policyManager.TriggerPolicyUpdates(true, "Named ports added or updated")
		}
	}()
	var ipsAdded []string
	if oldEndpoint != nil && oldEndpoint.Networking != nil {
		// Delete the old IP addresses from the IP cache
		defer func() {
			for _, oldPair := range oldEndpoint.Networking.Addressing {
				v4Added, v6Added := false, false
				for _, ipAdded := range ipsAdded {
					if ipAdded == oldPair.IPV4 {
						v4Added = true
					}
					if ipAdded == oldPair.IPV6 {
						v6Added = true
					}
				}
				if !v4Added {
					portsChanged := k.ipcache.DeleteOnMetadataMatch(oldPair.IPV4, source.CustomResource, endpoint.Namespace, endpoint.Name)
					if portsChanged {
						namedPortsChanged = true
					}
				}
				if !v6Added {
					portsChanged := k.ipcache.DeleteOnMetadataMatch(oldPair.IPV6, source.CustomResource, endpoint.Namespace, endpoint.Name)
					if portsChanged {
						namedPortsChanged = true
					}
				}
			}
		}()
	}

	// default to the standard key
	encryptionKey := node.GetIPsecKeyIdentity()

	id := identity.ReservedIdentityUnmanaged
	if endpoint.Identity != nil {
		id = identity.NumericIdentity(endpoint.Identity.ID)
	}

	if endpoint.Encryption != nil {
		encryptionKey = uint8(endpoint.Encryption.Key)
	}

	if endpoint.Networking == nil || endpoint.Networking.NodeIP == "" {
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

	if option.Config.EnableHighScaleIPcache &&
		!identity.IsWellKnownIdentity(id) {
		// Well-known identities are kept in the high-scale ipcache because we
		// need to be able to connect to the DNS pods to resolve FQDN policies.
		scopedLog := log.WithFields(logrus.Fields{
			logfields.Identity: id,
		})
		scopedLog.Debug("Endpoint is not well-known; skipping ipcache upsert")
		return
	}

	k8sMeta := &ipcache.K8sMetadata{
		Namespace:  endpoint.Namespace,
		PodName:    endpoint.Name,
		NamedPorts: make(ciliumTypes.NamedPortMap, len(endpoint.NamedPorts)),
	}
	for _, port := range endpoint.NamedPorts {
		p, err := u8proto.ParseProtocol(port.Protocol)
		if err != nil {
			continue
		}
		k8sMeta.NamedPorts[port.Name] = ciliumTypes.PortProto{
			Port:  port.Port,
			Proto: uint8(p),
		}
	}

	for _, pair := range endpoint.Networking.Addressing {
		if pair.IPV4 != "" {
			ipsAdded = append(ipsAdded, pair.IPV4)
			portsChanged, _ := k.ipcache.Upsert(pair.IPV4, nodeIP, encryptionKey, k8sMeta,
				ipcache.Identity{ID: id, Source: source.CustomResource})
			if portsChanged {
				namedPortsChanged = true
			}
		}

		if pair.IPV6 != "" {
			ipsAdded = append(ipsAdded, pair.IPV6)
			portsChanged, _ := k.ipcache.Upsert(pair.IPV6, nodeIP, encryptionKey, k8sMeta,
				ipcache.Identity{ID: id, Source: source.CustomResource})
			if portsChanged {
				namedPortsChanged = true
			}
		}
	}

	if k.egressGatewayManager != nil {
		k.egressGatewayManager.OnUpdateEndpoint(endpoint)
	}
}

func (k *K8sWatcher) endpointDeleted(endpoint *types.CiliumEndpoint) {
	if endpoint.Networking != nil {
		namedPortsChanged := false
		for _, pair := range endpoint.Networking.Addressing {
			if pair.IPV4 != "" {
				portsChanged := k.ipcache.DeleteOnMetadataMatch(pair.IPV4, source.CustomResource, endpoint.Namespace, endpoint.Name)
				if portsChanged {
					namedPortsChanged = true
				}
			}

			if pair.IPV6 != "" {
				portsChanged := k.ipcache.DeleteOnMetadataMatch(pair.IPV6, source.CustomResource, endpoint.Namespace, endpoint.Name)
				if portsChanged {
					namedPortsChanged = true
				}
			}
		}
		if namedPortsChanged {
			k.policyManager.TriggerPolicyUpdates(true, "Named ports deleted")
		}
	}
	if k.egressGatewayManager != nil {
		k.egressGatewayManager.OnDeleteEndpoint(endpoint)
	}
}

// CreateCiliumEndpointLocalPodIndexFunc returns an IndexFunc that indexes only local
// CiliumEndpoints, by their local Node IP.
func CreateCiliumEndpointLocalPodIndexFunc() cache.IndexFunc {
	nodeIP := node.GetCiliumEndpointNodeIP()
	return func(obj interface{}) ([]string, error) {
		cep, ok := obj.(*types.CiliumEndpoint)
		if !ok {
			return nil, fmt.Errorf("unexpected object type: %T", obj)
		}
		indices := []string{}
		if cep.Networking == nil {
			log.WithField("ciliumendpoint", cep.GetNamespace()+"/"+cep.GetName()).
				Debug("cannot index CiliumEndpoint by node without network status")
			return nil, nil
		}
		if cep.Networking.NodeIP == nodeIP {
			indices = append(indices, cep.Networking.NodeIP)
		}
		return indices, nil
	}
}
