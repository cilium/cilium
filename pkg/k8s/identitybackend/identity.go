// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package identitybackend

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	clientset "github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/types"
	k8sversion "github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	k8sTypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "crd-allocator")
)

func NewCRDBackend(c CRDBackendConfiguration) (allocator.Backend, error) {
	return &crdBackend{c}, nil
}

type CRDBackendConfiguration struct {
	NodeName string
	Store    cache.Store
	Client   clientset.Interface
	KeyType  allocator.AllocatorKey
}

type crdBackend struct {
	CRDBackendConfiguration
}

func (c *crdBackend) DeleteAllKeys() {
}

func toK8sLabels(old map[string]string) map[string]string {
	fixup := make(map[string]string, len(old))
	for k, v := range old {
		k = strings.ReplaceAll(k, ":", "_")
		fixup[k] = v
	}
	return fixup
}

func (c *crdBackend) AllocateID(ctx context.Context, id idpool.ID, key allocator.AllocatorKey) error {
	identity := &v2.CiliumIdentity{
		ObjectMeta: metav1.ObjectMeta{
			Name:   id.String(),
			Labels: toK8sLabels(key.GetAsMap()),
		},
		Status: v2.IdentityStatus{
			Nodes: map[string]metav1.Time{
				c.NodeName: metav1.Now(),
			},
		},
	}

	_, err := c.Client.CiliumV2().CiliumIdentities("default").Create(identity)
	return err
}

// JSONPatch structure based on the RFC 6902
type JSONPatch struct {
	OP    string      `json:"op,omitempty"`
	Path  string      `json:"path,omitempty"`
	Value interface{} `json:"value"`
}

func (c *crdBackend) AcquireReference(ctx context.Context, id idpool.ID, key allocator.AllocatorKey) error {
	identity := c.get(ctx, key)
	if identity == nil {
		return fmt.Errorf("identity does not exist")
	}

	capabilities := k8sversion.Capabilities()
	identityOps := c.Client.CiliumV2().CiliumIdentities("default")

	var err error
	if capabilities.Patch {
		var patch []byte
		patch, err = json.Marshal([]JSONPatch{
			{
				OP:    "test",
				Path:  "/status",
				Value: nil,
			},
			{
				OP:   "add",
				Path: "/status",
				Value: v2.IdentityStatus{
					Nodes: map[string]metav1.Time{
						c.NodeName: metav1.Now(),
					},
				},
			},
		})
		if err != nil {
			return err
		}

		_, err = identityOps.Patch(identity.GetName(), k8sTypes.JSONPatchType, patch, "status")
		if err != nil {
			patch, err = json.Marshal([]JSONPatch{
				{
					OP:    "replace",
					Path:  "/status/nodes/" + c.NodeName,
					Value: metav1.Now(),
				},
			})
			if err != nil {
				return err
			}
			_, err = identityOps.Patch(identity.GetName(), k8sTypes.JSONPatchType, patch, "status")
		}

		if err == nil {
			return nil
		}
	}

	identityCopy := identity.DeepCopy()
	if identityCopy.Status.Nodes == nil {
		identityCopy.Status.Nodes = map[string]metav1.Time{
			c.NodeName: metav1.Now(),
		}
	} else {
		identityCopy.Status.Nodes[c.NodeName] = metav1.Now()
	}

	if capabilities.UpdateStatus {
		_, err = identityOps.UpdateStatus(identityCopy.CiliumIdentity)
		if err == nil {
			return nil
		}
	}

	_, err = identityOps.Update(identityCopy.CiliumIdentity)
	return err
}

func (c *crdBackend) RunGC(staleKeysPrevRound map[string]uint64) (map[string]uint64, error) {
	return nil, nil
}

func (c *crdBackend) UpdateKey(id idpool.ID, key allocator.AllocatorKey, reliablyMissing bool) {
	if !reliablyMissing {
		if err := c.AcquireReference(context.TODO(), id, key); err == nil {
			return
		}
	}
}

func (c *crdBackend) Lock(ctx context.Context, key allocator.AllocatorKey) (allocator.Lock, error) {
	return &crdLock{}, nil
}

type crdLock struct{}

func (c *crdLock) Unlock() error {
	return nil
}

func (c *crdBackend) get(ctx context.Context, key allocator.AllocatorKey) *types.Identity {
	labels := toK8sLabels(key.GetAsMap())

	if c.Store == nil {
		return nil
	}

	for _, identityObject := range c.Store.List() {
		identity, ok := identityObject.(*types.Identity)
		if !ok {
			return nil
		}

		if reflect.DeepEqual(identity.Labels, labels) {
			return identity
		}
	}

	return nil
}

// Get returns the ID which is allocated to a key in the kvstore
func (c *crdBackend) Get(ctx context.Context, key allocator.AllocatorKey) (idpool.ID, error) {
	identity := c.get(ctx, key)
	if identity == nil {
		return idpool.NoID, nil
	}

	id, err := strconv.ParseUint(identity.Name, 10, 64)
	if err != nil {
		return idpool.NoID, fmt.Errorf("unable to parse value '%s': %s", identity.Name, err)
	}

	return idpool.ID(id), nil
}

// GetByID returns the key associated with an ID. Returns nil if no key is
// associated with the ID.
func (c *crdBackend) GetByID(id idpool.ID) (allocator.AllocatorKey, error) {
	if c.Store == nil {
		return nil, fmt.Errorf("store is not available yet")
	}

	identityTemplate := &types.Identity{
		CiliumIdentity: &v2.CiliumIdentity{
			ObjectMeta: metav1.ObjectMeta{
				Name: id.String(),
			},
		},
	}

	obj, exists, err := c.Store.Get(identityTemplate)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}

	identity, ok := obj.(*types.Identity)
	if !ok {
		return nil, fmt.Errorf("invalid object")
	}

	return c.KeyType.PutKeyFromMap(identity.Labels), nil
}

func (c *crdBackend) Release(ctx context.Context, key allocator.AllocatorKey) error {
	identity := c.get(ctx, key)
	if identity == nil {
		return fmt.Errorf("unable to release identity %s: identity does not exist", key)
	}

	if _, ok := identity.Status.Nodes[c.NodeName]; !ok {
		return fmt.Errorf("unable to release identity %s: identity is unused", key)
	}

	delete(identity.Status.Nodes, c.NodeName)

	capabilities := k8sversion.Capabilities()

	var err error
	identityOps := c.Client.CiliumV2().CiliumIdentities("default")
	if capabilities.Patch {
		var patch []byte
		patch, err = json.Marshal([]JSONPatch{
			{
				OP:   "delete",
				Path: "/status/nodes/" + c.NodeName,
			},
		})
		if err != nil {
			return err
		}
		_, err = identityOps.Patch(identity.GetName(), k8sTypes.JSONPatchType, patch, "status")
		if err == nil {
			return nil
		}
		/* fall through and attempt UpdateStatus() or Update() */
	}

	identityCopy := identity.DeepCopy()
	if identityCopy.Status.Nodes == nil {
		return nil
	}

	delete(identityCopy.Status.Nodes, c.NodeName)

	if capabilities.UpdateStatus {
		_, err = identityOps.UpdateStatus(identityCopy.CiliumIdentity)
		if err == nil {
			return nil
		}
	}

	_, err = identityOps.Update(identityCopy.CiliumIdentity)
	return err
}

func (c *crdBackend) ListAndWatch(handler allocator.CacheMutations, stopChan chan struct{}) {
	c.Store = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	identityInformer := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(c.Client.CiliumV2().RESTClient(),
			"ciliumidentities", v1.NamespaceAll, fields.Everything()),
		&v2.CiliumIdentity{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if identity, ok := obj.(*types.Identity); ok {
					if id, err := strconv.ParseUint(identity.Name, 10, 64); err == nil {
						handler.OnAdd(idpool.ID(id), c.KeyType.PutKeyFromMap(identity.Labels))
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if identity, ok := newObj.(*types.Identity); ok {
					if id, err := strconv.ParseUint(identity.Name, 10, 64); err == nil {
						handler.OnModify(idpool.ID(id), c.KeyType.PutKeyFromMap(identity.Labels))
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				if identity, ok := obj.(*types.Identity); ok {
					if id, err := strconv.ParseUint(identity.Name, 10, 64); err == nil {
						handler.OnDelete(idpool.ID(id), c.KeyType.PutKeyFromMap(identity.Labels))
					}
				}
			},
		},
		types.ConvertToIdentity,
		c.Store,
	)

	go func() {
		if ok := cache.WaitForCacheSync(stopChan, identityInformer.HasSynced); ok {
			handler.OnListDone()
		}
	}()

	identityInformer.Run(stopChan)
}

func (c *crdBackend) Status() (string, error) {
	return "OK", nil
}
