// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"encoding/json"
	"net"
	"path"
	"sort"

	k8sv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/k8s"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labels"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
)

type VMManager struct {
	ciliumClient      clientset.Interface
	identityAllocator *identityCache.CachingIdentityAllocator

	ciliumExternalWorkloadStore    cache.Store
	ciliumExternalWorkloadInformer cache.Controller

	backend kvstore.BackendOperations
}

func NewVMManager(clientset k8sClient.Clientset, backend kvstore.BackendOperations) *VMManager {
	m := &VMManager{
		ciliumClient: clientset,
		backend:      backend,
	}
	m.identityAllocator = identityCache.NewCachingIdentityAllocator(m)

	if option.Config.EnableWellKnownIdentities {
		identity.InitWellKnownIdentities(option.Config)
	}
	m.identityAllocator.InitIdentityAllocator(clientset)
	m.startCiliumExternalWorkloadWatcher(clientset)
	return m
}

func (m *VMManager) startCiliumExternalWorkloadWatcher(clientset k8sClient.Clientset) {
	m.ciliumExternalWorkloadStore, m.ciliumExternalWorkloadInformer = informer.NewInformer(
		cache.NewListWatchFromClient(clientset.CiliumV2().RESTClient(),
			ciliumv2.CEWPluralName, k8sv1.NamespaceAll, fields.Everything()),
		&ciliumv2.CiliumExternalWorkload{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if cew, ok := obj.(*ciliumv2.CiliumExternalWorkload); ok {
					log.Debugf("Added CEW: %v", cew)
				}
			},
			UpdateFunc: func(_, newObj interface{}) {
				if cew, ok := newObj.(*ciliumv2.CiliumExternalWorkload); ok {
					log.Debugf("Updated CEW: %v", cew)
				}
			},
			DeleteFunc: func(obj interface{}) {
				deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
				if ok {
					obj = deletedObj.Obj
				}
				if cew, ok := obj.(*ciliumv2.CiliumExternalWorkload); ok {
					log.Debugf("Deleted CEW: %v", cew)
				}
			},
		},
		k8s.ConvertToCiliumExternalWorkload,
	)

	go m.ciliumExternalWorkloadInformer.Run(wait.NeverStop)
}

//
// IdentityAllocatorOwner interface
//

// UpdateIdentities will be called when identities have changed
func (m *VMManager) UpdateIdentities(added, deleted identityCache.IdentityCache) {}

// GetNodeSuffix must return the node specific suffix to use
func (m *VMManager) GetNodeSuffix() string {
	return "vm-allocator"
}

func nodeOverrideFromCEW(n *nodeTypes.RegisterNode, cew *ciliumv2.CiliumExternalWorkload) *nodeTypes.RegisterNode {
	nk := n.DeepCopy()

	nk.Labels = make(map[string]string, len(cew.Labels))
	for k, v := range cew.Labels {
		nk.Labels[k] = v
	}

	// Default pod name and namespace labels
	if nk.Labels[k8sConst.PodNamespaceLabel] == "" {
		nk.Labels[k8sConst.PodNamespaceLabel] = "default"
	}
	if nk.Labels[k8sConst.PodNameLabel] == "" {
		nk.Labels[k8sConst.PodNameLabel] = cew.Name
	}

	// Override cluster
	nk.Cluster = cfg.clusterName
	nk.ClusterID = cfg.clusterID
	nk.Labels[k8sConst.PolicyLabelCluster] = cfg.clusterName

	// Override CIDRs if defined
	if cew.Spec.IPv4AllocCIDR != "" {
		if cidr, err := cidr.ParseCIDR(cew.Spec.IPv4AllocCIDR); err == nil {
			if ip4 := cidr.IP.To4(); ip4 != nil {
				nk.IPv4AllocCIDR = cidr
			} else {
				log.Warning("CEW: ipv4-alloc-cidr is not IPv4")
			}
		} else {
			log.WithError(err).Warningf("CEW: parse error on %s", cew.Spec.IPv4AllocCIDR)
		}
	}
	if cew.Spec.IPv6AllocCIDR != "" {
		if cidr, err := cidr.ParseCIDR(cew.Spec.IPv6AllocCIDR); err == nil {
			if ip6 := cidr.IP.To16(); ip6 != nil {
				nk.IPv6AllocCIDR = cidr
			} else {
				log.Warning("CEW: ipv6-alloc-cidr is not IPv6")
			}
		} else {
			log.WithError(err).Warningf("CEW: parse error on %s", cew.Spec.IPv6AllocCIDR)
		}
	}
	return nk
}

//
// Observer interface
//

func (m *VMManager) OnUpdate(k store.Key) {
	if n, ok := k.(*nodeTypes.RegisterNode); ok {
		// Only handle registration events if CiliumExternalWorkload CRD with a matching name exists
		cewObj, exists, _ := m.ciliumExternalWorkloadStore.GetByKey(n.Name)
		if !exists {
			log.Warningf("CEW: CiliumExternalWorkload resource not found for: %v", n)
			return
		}
		cew, ok := cewObj.(*ciliumv2.CiliumExternalWorkload)
		if !ok {
			log.Errorf("CEW: CiliumExternalWorkload %s not the right type: %T", n.Name, cewObj)
			return
		}

		if n.NodeIdentity == 0 {
			// Phase 1: Initial registration with zero ID, return configuration
			nk := nodeOverrideFromCEW(n, cew)

			log.Debugf("CEW: VM Cilium Node updated: %v -> %v", n, nk)
			// FIXME: GH-17909 Balance this call with a call to release the identity.
			id := m.AllocateNodeIdentity(nk)
			if id != nil {
				nid := id.ID.Uint32()
				nk.NodeIdentity = nid

				// clear addresses so that we know the registration is not ready yet
				nk.IPAddresses = nil

				// Update the registration, now with the node identity and overridden fields
				if err := m.syncKVStoreKey(context.Background(), nk); err != nil {
					log.WithError(err).Warning("CEW: Unable to update register node in etcd")
				} else {
					log.Debugf("CEW: Updated register node in etcd (nid: %d): %v", nid, nk)
				}
			}
		} else if len(n.IPAddresses) > 0 {
			// Phase 2: non-zero ID registration with addresses

			// Override again, just in case the external node is misbehaving
			nk := nodeOverrideFromCEW(n, cew)

			id := m.LookupNodeIdentity(nk)
			if id == nil || id.ID.Uint32() != nk.NodeIdentity {
				log.Errorf("CEW: Invalid identity %d in %v", nk.NodeIdentity, nk)
			}

			// Create cluster resources for the external node
			nodeIP := nk.GetNodeIP(false)
			m.UpdateCiliumNodeResource(nk, cew)
			m.UpdateCiliumEndpointResource(nk.Name, id, nk.IPAddresses, nodeIP)

			nid := id.ID.Uint32()

			// Update CEW with the identity and IP
			cewCopy := cew.DeepCopy()
			cewCopy.Status.ID = uint64(nid)
			cewCopy.Status.IP = nodeIP.String()
			for retryCount := 0; retryCount < maxRetryCount; retryCount++ {
				if _, err := m.ciliumClient.CiliumV2().CiliumExternalWorkloads().UpdateStatus(context.TODO(), cewCopy, metav1.UpdateOptions{}); err != nil {
					if errors.IsConflict(err) {
						log.WithError(err).Warn("CEW: Unable to update CiliumExternalWorkload status, will retry")
						continue
					}
					log.WithError(err).Error("CEW: Unable to update CiliumExternalWorkload status")
				} else {
					log.Debugf("CEW: Successfully updated CiliumExternalWorkload status: %v", *cewCopy)
					break
				}
			}
		}
	} else {
		log.Errorf("CEW: VM Cilium Node not RegisterNode: %v", k)
	}
}

func (m *VMManager) OnDelete(k store.NamedKey) {
	log.Debugf("RegisterNode deleted: %v", k.GetKeyName())
}

func (m *VMManager) AllocateNodeIdentity(n *nodeTypes.RegisterNode) *identity.Identity {
	vmLabels := labels.Map2Labels(n.Labels, "k8s")

	log.Debug("Resolving identity for VM labels")
	ctx, cancel := context.WithTimeout(context.TODO(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()

	id := m.identityAllocator.LookupIdentity(ctx, vmLabels)
	if id != nil {
		return id
	}

	id, allocated, err := m.identityAllocator.AllocateIdentity(ctx, vmLabels, true, identity.InvalidIdentity)
	if err != nil {
		log.WithError(err).Error("unable to resolve identity")
	} else {
		if allocated {
			log.Debugf("allocated identity %v", id)
		} else {
			log.Debugf("identity %v was already allocated", id)
		}
	}
	return id
}

func (m *VMManager) LookupNodeIdentity(n *nodeTypes.RegisterNode) *identity.Identity {
	vmLabels := labels.Map2Labels(n.Labels, "k8s")

	log.Debug("Looking up identity for VM labels")
	ctx, cancel := context.WithTimeout(context.TODO(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()

	return m.identityAllocator.LookupIdentity(ctx, vmLabels)
}

const (
	maxRetryCount = 5
)

// UpdateCiliumNodeResource updates the CiliumNode resource representing the
// local node
func (m *VMManager) UpdateCiliumNodeResource(n *nodeTypes.RegisterNode, cew *ciliumv2.CiliumExternalWorkload) {
	nr := n.ToCiliumNode()
	nr.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion: ciliumv2.SchemeGroupVersion.String(),
			Kind:       ciliumv2.CEWKindDefinition,
			Name:       cew.GetName(),
			UID:        cew.GetUID(),
		},
	}

	for retryCount := 0; retryCount < maxRetryCount; retryCount++ {
		log.Info("Getting CN during an update")
		nodeResource, err := m.ciliumClient.CiliumV2().CiliumNodes().Get(context.TODO(), n.Name, metav1.GetOptions{})
		if err != nil {
			if _, err = m.ciliumClient.CiliumV2().CiliumNodes().Create(context.TODO(), nr, metav1.CreateOptions{}); err != nil {
				if errors.IsConflict(err) {
					log.WithError(err).Warn("Unable to create CiliumNode resource, will retry")
					continue
				}
				log.WithError(err).Fatal("Unable to create CiliumNode resource")
			} else {
				log.Infof("Successfully created CiliumNode resource: %v", *nr)
				return
			}
		} else {
			nodeResource.ObjectMeta.Labels = nr.ObjectMeta.Labels
			nodeResource.Spec = nr.Spec
			if _, err := m.ciliumClient.CiliumV2().CiliumNodes().Update(context.TODO(), nodeResource, metav1.UpdateOptions{}); err != nil {
				if errors.IsConflict(err) {
					log.WithError(err).Warn("Unable to update CiliumNode resource, will retry")
					continue
				}
				log.WithError(err).Fatal("Unable to update CiliumNode resource")
			} else {
				log.Infof("Successfully updated CiliumNode resource: %v", *nodeResource)
				return
			}
		}
	}
	log.Fatal("Could not create or update CiliumNode resource, despite retries")
}

// UpdateCiliumEndpointResource updates the CiliumNode resource representing the
// local node
func (m *VMManager) UpdateCiliumEndpointResource(name string, id *identity.Identity, ipAddresses []nodeTypes.Address, nodeIP net.IP) {
	var addresses []*ciliumv2.AddressPair
	i := 0
	for _, addr := range ipAddresses {
		if len(addresses) == i {
			addresses = append(addresses, &ciliumv2.AddressPair{})
		}
		if ipv4 := addr.IP.To4(); ipv4 != nil {
			if addresses[i].IPV4 != "" {
				addresses = append(addresses, &ciliumv2.AddressPair{})
				i++
			}
			addresses[i].IPV4 = ipv4.String()
		} else if ipv6 := addr.IP.To16(); ipv6 != nil {
			if addresses[i].IPV6 != "" {
				addresses = append(addresses, &ciliumv2.AddressPair{})
				i++
			}
			addresses[i].IPV6 = ipv6.String()
		}
	}

	namespace := id.Labels[k8sConst.PodNamespaceLabel].Value

	var localCEP *ciliumv2.CiliumEndpoint
	for retryCount := 0; retryCount < maxRetryCount; retryCount++ {
		log.Info("Getting Node during an CEP update")
		nr, err := m.ciliumClient.CiliumV2().CiliumNodes().Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			log.WithError(err).Warn("Unable to get CiliumNode resource, will retry")
			continue
		}
		log.Info("Getting CEP during an initialization")
		_, err = m.ciliumClient.CiliumV2().CiliumEndpoints(namespace).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			cep := &ciliumv2.CiliumEndpoint{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
					OwnerReferences: []metav1.OwnerReference{{
						APIVersion: "cilium.io/v2",
						Kind:       "CiliumNode",
						Name:       nr.ObjectMeta.Name,
						UID:        nr.ObjectMeta.UID,
					}},
					Labels: map[string]string{
						"name": name,
					},
				},
			}
			if localCEP, err = m.ciliumClient.CiliumV2().CiliumEndpoints(namespace).Create(context.TODO(), cep, metav1.CreateOptions{}); err != nil {
				if errors.IsConflict(err) {
					log.WithError(err).Warn("Unable to create CiliumEndpoint resource, will retry")
					continue
				}
				log.WithError(err).Fatal("Unable to create CiliumEndpoint resource")
			}
			js, _ := json.Marshal(cep)
			log.Infof("Successfully created CiliumEndpoint resource %s/%s: %s", namespace, name, js)
			js, _ = json.Marshal(localCEP)
			log.Infof("Returned CiliumEndpoint resource %s/%s: %s", namespace, name, js)
		}

		mdl := ciliumv2.EndpointStatus{
			ID: int64(1),
			// ExternalIdentifiers: e.getModelEndpointIdentitiersRLocked(),
			Identity: getEndpointIdentity(identitymodel.CreateModel(id)),
			Networking: &ciliumv2.EndpointNetworking{
				Addressing: addresses,
				NodeIP:     nodeIP.String(),
			},
			State: string(models.EndpointStateReady), // XXX
			// Encryption: ciliumv2.EncryptionSpec{Key: int(n.GetIPsecKeyIdentity())},
			// NamedPorts: e.getNamedPortsModel(),
		}

		replaceCEPStatus := []k8s.JSONPatch{
			{
				OP:    "replace",
				Path:  "/status",
				Value: mdl,
			},
		}
		var createStatusPatch []byte
		createStatusPatch, err = json.Marshal(replaceCEPStatus)
		if err != nil {
			log.WithError(err).Fatalf("json.Marshal(%v) failed", replaceCEPStatus)
		}
		localCEP, err = m.ciliumClient.CiliumV2().CiliumEndpoints(namespace).Patch(context.TODO(), name,
			types.JSONPatchType, createStatusPatch, metav1.PatchOptions{})
		if err != nil {
			if errors.IsConflict(err) {
				log.WithError(err).Warn("Unable to update CiliumEndpoint resource, will retry")
				continue
			}
			log.WithError(err).Fatal("Unable to update CiliumEndpoint resource")
		} else {
			log.Infof("Successfully patched CiliumEndpoint resource: %v", *localCEP)
			return
		}
	}
	log.Fatal("Could not create or update CiliumEndpoint resource, despite retries")
}

func getEndpointIdentity(mdlIdentity *models.Identity) (identity *ciliumv2.EndpointIdentity) {
	if mdlIdentity == nil {
		return
	}
	identity = &ciliumv2.EndpointIdentity{
		ID: mdlIdentity.ID,
	}

	identity.Labels = make([]string, len(mdlIdentity.Labels))
	copy(identity.Labels, mdlIdentity.Labels)
	sort.Strings(identity.Labels)
	log.Infof("Got Endpoint Identity: %v", *identity)
	return
}

// syncKVStoreKey synchronizes a key to the kvstore
func (m *VMManager) syncKVStoreKey(ctx context.Context, key store.LocalKey) error {
	jsonValue, err := key.Marshal()
	if err != nil {
		return err
	}

	// Update key in kvstore, overwrite an eventual existing key, attach
	// lease to expire entry when agent dies and never comes back up.
	k := path.Join(nodeStore.NodeRegisterStorePrefix, key.GetKeyName())
	if _, err := m.backend.UpdateIfDifferent(ctx, k, jsonValue, true); err != nil {
		return err
	}

	return nil
}
