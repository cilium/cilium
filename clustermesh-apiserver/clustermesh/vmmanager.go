// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"path"
	"slices"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/identity"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/k8s"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
)

var externalWorkloadsCell = cell.Module(
	"external-workloads",
	"External workloads",

	cell.Config(
		// The default value is set to true to match the existing behavior in case
		// the flag is not configured (for instance by the legacy cilium CLI).
		ExternalWorkloadsConfig{EnableExternalWorkloads: true},
	),

	cell.Provide(externalWorkloadsProvider),
	cell.Invoke(func(*VMManager) {}),
)

type ExternalWorkloadsConfig struct {
	EnableExternalWorkloads bool
}

func (def ExternalWorkloadsConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-external-workloads", def.EnableExternalWorkloads, "Enable support for external workloads")
}

func externalWorkloadsProvider(
	lc cell.Lifecycle,

	cfg ExternalWorkloadsConfig,
	clusterInfo cmtypes.ClusterInfo,

	clientset k8sClient.Clientset,
	crdSyncPromise promise.Promise[synced.CRDSync],
	ciliumExternalWorkloads resource.Resource[*ciliumv2.CiliumExternalWorkload],
	backendPromise promise.Promise[kvstore.BackendOperations],
) *VMManager {
	if !cfg.EnableExternalWorkloads {
		return nil
	}

	// External workloads require CRD allocation mode
	option.Config.IdentityAllocationMode = option.IdentityAllocationModeCRD
	option.Config.AllocatorListTimeout = defaults.AllocatorListTimeout

	mgr := &VMManager{
		clusterInfo:  clusterInfo,
		ciliumClient: clientset,
	}

	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			_, err := crdSyncPromise.Await(ctx)
			if err != nil {
				return fmt.Errorf("Wait for CRD resources failed: %w", err)
			}

			ewstore, err := ciliumExternalWorkloads.Store(ctx)
			if err != nil {
				return fmt.Errorf("unable to retrieve CiliumExternalWorkloads store: %w", err)
			}

			backend, err := backendPromise.Await(ctx)
			if err != nil {
				return err
			}

			mgr.ciliumExternalWorkloadStore = ewstore
			mgr.backend = backend
			mgr.identityAllocator = identityCache.NewCachingIdentityAllocator(mgr, identityCache.AllocatorConfig{})
			mgr.identityAllocator.InitIdentityAllocator(clientset)

			if _, err = store.JoinSharedStore(store.Configuration{
				Backend:              backend,
				Prefix:               nodeStore.NodeRegisterStorePrefix,
				KeyCreator:           nodeStore.RegisterKeyCreator,
				SharedKeyDeleteDelay: defaults.NodeDeleteDelay,
				Observer:             mgr,
			}); err != nil {
				return fmt.Errorf("unable to set up node register store: %w", err)
			}

			return nil
		},
	})

	return mgr
}

type VMManager struct {
	clusterInfo cmtypes.ClusterInfo

	ciliumClient      clientset.Interface
	identityAllocator *identityCache.CachingIdentityAllocator

	ciliumExternalWorkloadStore resource.Store[*ciliumv2.CiliumExternalWorkload]

	backend kvstore.BackendOperations
}

//
// IdentityAllocatorOwner interface
//

// UpdateIdentities will be called when identities have changed
func (m *VMManager) UpdateIdentities(added, deleted identity.IdentityMap) {}

// GetNodeSuffix must return the node specific suffix to use
func (m *VMManager) GetNodeSuffix() string {
	return "vm-allocator"
}

func (m *VMManager) nodeOverrideFromCEW(n *nodeTypes.RegisterNode, cew *ciliumv2.CiliumExternalWorkload) *nodeTypes.RegisterNode {
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
	nk.Cluster = m.clusterInfo.Name
	nk.ClusterID = m.clusterInfo.ID
	nk.Labels[k8sConst.PolicyLabelCluster] = m.clusterInfo.Name

	// Override CIDRs if defined
	if cew.Spec.IPv4AllocCIDR != "" {
		if cidr, err := cidr.ParseCIDR(cew.Spec.IPv4AllocCIDR); err == nil {
			if ip4 := cidr.IP.To4(); ip4 != nil {
				nk.IPv4AllocCIDR = cidr
			} else {
				log.Warn("CEW: ipv4-alloc-cidr is not IPv4")
			}
		} else {
			log.Warn(
				"CEW: parse error on %s",
				slog.Any(logfields.Error, err),
				slog.String("ipv4-cidr", cew.Spec.IPv4AllocCIDR),
			)
		}
	}
	if cew.Spec.IPv6AllocCIDR != "" {
		if cidr, err := cidr.ParseCIDR(cew.Spec.IPv6AllocCIDR); err == nil {
			if ip6 := cidr.IP.To16(); ip6 != nil {
				nk.IPv6AllocCIDR = cidr
			} else {
				log.Warn("CEW: ipv6-alloc-cidr is not IPv6")
			}
		} else {
			log.Warn(
				"CEW: parse error",
				slog.Any(logfields.Error, err),
				slog.String("ipv6-cidr", cew.Spec.IPv6AllocCIDR),
			)
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
		cew, exists, _ := m.ciliumExternalWorkloadStore.GetByKey(resource.Key{Name: n.Name})
		if !exists {
			log.Warn("CEW: CiliumExternalWorkload resource not found", slog.Any("node", n))
			return
		}

		if n.NodeIdentity == 0 {
			// Phase 1: Initial registration with zero ID, return configuration
			nk := m.nodeOverrideFromCEW(n, cew)

			log.Debug("CEW: VM Cilium Node updated", slog.Any("node", n), slog.Any("nk", nk))
			// FIXME: GH-17909 Balance this call with a call to release the identity.
			id := m.AllocateNodeIdentity(nk)
			if id != nil {
				nid := id.ID.Uint32()
				nk.NodeIdentity = nid

				// clear addresses so that we know the registration is not ready yet
				nk.IPAddresses = nil

				// Update the registration, now with the node identity and overridden fields
				if err := m.syncKVStoreKey(context.Background(), nk); err != nil {
					log.Warn("CEW: Unable to update register node in etcd", slog.Any(logfields.Error, err))
				} else {
					log.Debug("CEW: Updated register node in etcd", slog.Uint64("nid", uint64(nid)), slog.Any("nk", nk))
				}
			}
		} else if len(n.IPAddresses) > 0 {
			// Phase 2: non-zero ID registration with addresses

			// Override again, just in case the external node is misbehaving
			nk := m.nodeOverrideFromCEW(n, cew)

			id := m.LookupNodeIdentity(nk)
			if id == nil || id.ID.Uint32() != nk.NodeIdentity {
				log.Error(
					"CEW: Invalid identity",
					slog.Uint64("node-identity", uint64(nk.NodeIdentity)),
					slog.Any("nk", nk),
				)
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
						log.Warn("CEW: Unable to update CiliumExternalWorkload status, will retry", slog.Any(logfields.Error, err))
						continue
					}
					log.Error("CEW: Unable to update CiliumExternalWorkload status", slog.Any(logfields.Error, err))
				} else {
					log.Debug(
						"CEW: Successfully updated CiliumExternalWorkload status",
						slog.Any("cewCopy", *cewCopy),
					)
					break
				}
			}
		}
	} else {
		log.Error(
			"CEW: VM Cilium Node not RegisterNode",
			slog.Any("node", k),
		)
	}
}

func (m *VMManager) OnDelete(k store.NamedKey) {
	log.Debug(
		"RegisterNode deleted",
		slog.String("node-name", k.GetKeyName()),
	)
}

func (m *VMManager) AllocateNodeIdentity(n *nodeTypes.RegisterNode) *identity.Identity {
	vmLabels := labels.Map2Labels(n.Labels, labels.LabelSourceK8s)

	log.Debug("Resolving identity for VM labels")
	ctx, cancel := context.WithTimeout(context.TODO(), option.Config.KVstoreConnectivityTimeout)
	defer cancel()

	id := m.identityAllocator.LookupIdentity(ctx, vmLabels)
	if id != nil {
		return id
	}

	id, allocated, err := m.identityAllocator.AllocateIdentity(ctx, vmLabels, true, identity.InvalidIdentity)
	if err != nil {
		log.Error("unable to resolve identity", slog.Any(logfields.Error, err))
	} else {
		if allocated {
			log.Debug(
				"allocated identity",
				slog.Any("id", id),
			)
		} else {
			log.Debug(
				"identity was already allocated",
				slog.Any("id", id),
			)
		}
	}
	return id
}

func (m *VMManager) LookupNodeIdentity(n *nodeTypes.RegisterNode) *identity.Identity {
	vmLabels := labels.Map2Labels(n.Labels, labels.LabelSourceK8s)

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
					log.Warn("Unable to create CiliumNode resource, will retry", slog.Any(logfields.Error, err))
					continue
				}
				logging.Fatal(log, "Unable to create CiliumNode resource", slog.Any(logfields.Error, err))
			} else {
				log.Info("Successfully created CiliumNode resource", slog.Any("node", *nr))
				return
			}
		} else {
			nodeResource.ObjectMeta.Labels = nr.ObjectMeta.Labels
			nodeResource.Spec = nr.Spec
			if _, err := m.ciliumClient.CiliumV2().CiliumNodes().Update(context.TODO(), nodeResource, metav1.UpdateOptions{}); err != nil {
				if errors.IsConflict(err) {
					log.Warn("Unable to update CiliumNode resource, will retry", slog.Any(logfields.Error, err))
					continue
				}
				logging.Fatal(log, "Unable to update CiliumNode resource", slog.Any(logfields.Error, err))
			} else {
				log.Info("Successfully updated CiliumNode resource", slog.Any("node", *nodeResource))
				return
			}
		}
	}
	logging.Fatal(log, "Could not create or update CiliumNode resource, despite retries")
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
			log.Warn("Unable to get CiliumNode resource, will retry", slog.Any(logfields.Error, err))
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
					log.Warn("Unable to create CiliumEndpoint resource, will retry", slog.Any(logfields.Error, err))
					continue
				}
				logging.Fatal(log, "Unable to create CiliumEndpoint resource", slog.Any(logfields.Error, err))
			}
			js, _ := json.Marshal(cep)
			log.Info(
				"Successfully created CiliumEndpoint resource",
				slog.String("namespace", namespace),
				slog.String("name", name),
				slog.String("resource", string(js)),
			)
			js, _ = json.Marshal(localCEP)
			log.Info(
				"Returned CiliumEndpoint resource",
				slog.String("namespace", namespace),
				slog.String("name", name),
				slog.String("resource", string(js)),
			)
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
			logging.Fatal(log, fmt.Sprintf("json.Marshal(%v) failed", replaceCEPStatus), slog.Any(logfields.Error, err))
		}
		localCEP, err = m.ciliumClient.CiliumV2().CiliumEndpoints(namespace).Patch(context.TODO(), name,
			types.JSONPatchType, createStatusPatch, metav1.PatchOptions{})
		if err != nil {
			if errors.IsConflict(err) {
				log.Warn("Unable to update CiliumEndpoint resource, will retry", slog.Any(logfields.Error, err))
				continue
			}
			logging.Fatal(log, "Unable to update CiliumEndpoint resource", slog.Any(logfields.Error, err))
		} else {
			log.Info("Successfully patched CiliumEndpoint resource", slog.Any("cep", *localCEP))
			return
		}
	}
	logging.Fatal(log, "Could not create or update CiliumEndpoint resource, despite retries")
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
	slices.Sort(identity.Labels)
	log.Info("Got Endpoint Identity", slog.Any("identity", *identity))
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
