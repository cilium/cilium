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

package main

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

var identityStore cache.Store

func deleteIdentity(identity *types.Identity) error {
	err := ciliumK8sClient.CiliumV2().CiliumIdentities().Delete(
		identity.Name,
		&metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{
				UID:             &identity.UID,
				ResourceVersion: &identity.ResourceVersion,
			},
		})
	if err != nil {
		log.WithError(err).Error("Unable to delete identity")
	}

	return err
}

func identityGCIteration() {
	if identityStore == nil {
		return
	}

nextIdentity:
	for _, identityObject := range identityStore.List() {
		identity, ok := identityObject.(*types.Identity)
		if !ok {
			continue
		}

		for _, heartbeat := range identity.Status.Nodes {
			if time.Since(heartbeat.Time) < k8sIdentityHeartbeatTimeout {
				continue nextIdentity
			}
		}

		log.WithFields(logrus.Fields{
			logfields.Identity: identity,
			"nodes":            identity.Status.Nodes,
		}).Debug("Deleting unused identity")
		deleteIdentity(identity)
	}
}

func startCRDIdentityGC() {
	controller.NewManager().UpdateController("crd-identity-gc",
		controller.ControllerParams{
			RunInterval: identityGCInterval,
			DoFunc: func(ctx context.Context) error {
				identityGCIteration()
				return nil
			},
		})
}

func handleIdentityUpdate(identity *types.Identity) {
	// If no more nodes are using this identity, release the ID for reuse
	if len(identity.Status.Nodes) == 0 {
		deleteIdentity(identity)
	}
}

func startManagingK8sIdentities() {
	identityStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	identityInformer := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumK8sClient.CiliumV2().RESTClient(),
			"ciliumidentities", v1.NamespaceAll, fields.Everything()),
		&v2.CiliumIdentity{},
		0,
		cache.ResourceEventHandlerFuncs{
			UpdateFunc: func(oldObj, newObj interface{}) {
				if identity, ok := newObj.(*types.Identity); ok {
					handleIdentityUpdate(identity)
				}
			},
		},
		types.ConvertToIdentity,
		identityStore,
	)

	go identityInformer.Run(wait.NeverStop)
}
