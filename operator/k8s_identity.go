// Copyright 2019-2020 Authors of Cilium
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

	"github.com/cilium/cilium/operator/identity"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

var identityStore cache.Store

// deleteIdentity deletes an identity. It includes the resource version and
// will error if the object has since been changed.
func deleteIdentity(ctx context.Context, identity *v2.CiliumIdentity) error {
	// Wait until we can delete an identity
	err := identityRateLimiter.Wait(ctx)
	if err != nil {
		return err
	}
	err = ciliumK8sClient.CiliumV2().CiliumIdentities().Delete(
		ctx,
		identity.Name,
		metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{
				UID:             &identity.UID,
				ResourceVersion: &identity.ResourceVersion,
			},
		})
	if err != nil {
		log.WithError(err).Error("Unable to delete identity")
	} else {
		log.WithFields(logrus.Fields{"identity": identity.GetName()}).Info("Garbage collected identity")
	}

	return err
}

var identityHeartbeat *identity.IdentityHeartbeatStore

// identityGCIteration is a single iteration of a garbage collection. It will
// delete identities that have not had its heartbeat lifesign updated since
// option.Config.IdentityHeartbeatTimeout
func identityGCIteration(ctx context.Context) {
	log.Debug("Running CRD identity garbage collector")

	if identityStore == nil {
		log.Debug("Identity store cache is not ready yet")
		return
	}
	select {
	case <-watchers.CiliumEndpointsSynced:
	case <-ctx.Done():
		return
	}

	timeNow := time.Now()
	for _, identityObject := range identityStore.List() {
		identity, ok := identityObject.(*v2.CiliumIdentity)
		if !ok {
			log.WithField(logfields.Object, identityObject).
				Errorf("Saw %T object while expecting k8s/types.Identity", identityObject)
			continue
		}

		// The identity is definitely alive if there's a CE using it.
		if watchers.HasCEWithIdentity(identity.Name) {
			// If the identity is alive then mark it as alive
			identityHeartbeat.MarkAlive(identity.Name, timeNow)
			continue
		}
		if !identityHeartbeat.IsAlive(identity.Name) {
			log.WithFields(logrus.Fields{
				logfields.Identity: identity,
				"nodes":            identity.Status.Nodes,
			}).Debug("Deleting unused identity")
			if err := deleteIdentity(ctx, identity); err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.Identity: identity,
					"nodes":            identity.Status.Nodes,
				}).Error("Deleting unused identity")
				// If Context was canceled we should break
				if ctx.Err() != nil {
					break
				}
			}
		}
	}

	identityHeartbeat.GC()
}

func startCRDIdentityGC() {
	if operatorOption.Config.EndpointGCInterval == 0 {
		log.Fatal("The CiliumIdentity garbage collector requires the CiliumEndpoint garbage collector to be enabled")
	}

	log.Infof("Starting CRD identity garbage collector with %s interval...", operatorOption.Config.IdentityGCInterval)

	controller.NewManager().UpdateController("crd-identity-gc",
		controller.ControllerParams{
			RunInterval: operatorOption.Config.IdentityGCInterval,
			DoFunc: func(ctx context.Context) error {
				identityGCIteration(ctx)
				return ctx.Err()
			},
		})
}

// startManagingK8sIdentities waits for the CiliumIdentity CRD availability and
// then garbage collects CiliumIdentity resources.
func startManagingK8sIdentities(apiextensionsK8sClient apiextensionsclientset.Interface) error {
	identityHeartbeat = identity.NewIdentityHeartbeatStore(operatorOption.Config.IdentityHeartbeatTimeout)

	identityStore = cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)
	identityInformer := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(ciliumK8sClient.CiliumV2().RESTClient(),
			v2.CIDPluralName, v1.NamespaceAll, fields.Everything()),
		&v2.CiliumIdentity{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				if identity, ok := obj.(*v2.CiliumIdentity); ok {
					// A new identity is always alive
					identityHeartbeat.MarkAlive(identity.Name, time.Now())
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				if oldIdty, ok := oldObj.(*v2.CiliumIdentity); ok {
					if newIdty, ok := newObj.(*v2.CiliumIdentity); ok {
						if oldIdty.DeepEqual(newIdty) {
							return
						}
						// Any update to the identity marks it as alive
						identityHeartbeat.MarkAlive(newIdty.Name, time.Now())
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				identity, ok := obj.(*v2.CiliumIdentity)
				if !ok {
					deletedObj, ok := obj.(cache.DeletedFinalStateUnknown)
					if ok {
						identity, ok = deletedObj.Obj.(*v2.CiliumIdentity)
					}
					if !ok {
						return
					}
				}
				// When the identity is deleted, delete the
				// heartbeat entry as well. This will not be
				// 100% accurate as the CiliumEndpoint can live
				// longer than the CiliumIdentity. See
				// identityHeartbeat.GC()
				identityHeartbeat.Delete(identity.Name)
			},
		},
		nil,
		identityStore,
	)

	if err := WaitForCRD(apiextensionsK8sClient, v2.CIDName); err != nil {
		return err
	}
	go identityInformer.Run(wait.NeverStop)
	return nil
}
