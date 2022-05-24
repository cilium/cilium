// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/operator/identity"
	"github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/controller"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
		log.WithField(logfields.Identity, identity.GetName()).Info("Garbage collected identity")
	}

	return err
}

func updateIdentity(ctx context.Context, identity *v2.CiliumIdentity) error {
	_, err := ciliumK8sClient.CiliumV2().CiliumIdentities().Update(
		ctx,
		identity,
		metav1.UpdateOptions{})
	if err != nil {
		log.WithError(err).Error("Updating Identity")
	} else {
		log.WithField(logfields.Identity, identity.GetName()).Debug("Updated identity")
	}

	return err
}

var identityHeartbeat *identity.IdentityHeartbeatStore

// counters for GC failed/successful runs
var (
	failedRuns     = 0
	successfulRuns = 0
)

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

	identityStoreList := identityStore.List()
	totalEntries := len(identityStoreList)
	deletedEntries := 0

	timeNow := time.Now()
	for _, identityObject := range identityStoreList {
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
			ts, ok := identity.Annotations[identitybackend.HeartBeatAnnotation]
			if !ok {
				identity = identity.DeepCopy()
				if identity.Annotations == nil {
					identity.Annotations = make(map[string]string)
				}
				log.WithField(logfields.Identity, identity).Info("Marking identity for later deletion")
				identity.Annotations[identitybackend.HeartBeatAnnotation] = timeNow.Format(time.RFC3339Nano)
				err := updateIdentity(ctx, identity)
				if err != nil {
					log.WithError(err).
						WithField(logfields.Identity, identity).
						Error("Marking identity for later deletion")
				}
				continue
			}

			log.WithFields(logrus.Fields{
				logfields.Identity: identity,
			}).Debugf("Deleting unused identity; marked for deletion at %s", ts)
			if err := deleteIdentity(ctx, identity); err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.Identity: identity,
				}).Error("Deleting unused identity")
				// If Context was canceled we should break
				if ctx.Err() != nil {
					break
				}
			} else {
				deletedEntries++
			}
		}
	}

	if operatorOption.Config.EnableMetrics {
		if ctx.Err() == nil {
			successfulRuns++
			metrics.IdentityGCRuns.WithLabelValues(metrics.LabelValueOutcomeSuccess).Set(float64(successfulRuns))
		} else {
			failedRuns++
			metrics.IdentityGCRuns.WithLabelValues(metrics.LabelValueOutcomeFail).Set(float64(failedRuns))
		}
		aliveEntries := totalEntries - deletedEntries
		metrics.IdentityGCSize.WithLabelValues(metrics.LabelValueOutcomeAlive).Set(float64(aliveEntries))
		metrics.IdentityGCSize.WithLabelValues(metrics.LabelValueOutcomeDeleted).Set(float64(deletedEntries))
	}

	identityHeartbeat.GC()
}

func startCRDIdentityGC() {
	if operatorOption.Config.EndpointGCInterval == 0 {
		log.Fatal("The CiliumIdentity garbage collector requires the CiliumEndpoint garbage collector to be enabled")
	}

	log.WithField(logfields.Interval, operatorOption.Config.IdentityGCInterval).Info("Starting CRD identity garbage collector")

	controller.NewManager().UpdateController("crd-identity-gc",
		controller.ControllerParams{
			RunInterval: operatorOption.Config.IdentityGCInterval,
			DoFunc: func(ctx context.Context) error {
				identityGCIteration(ctx)
				return ctx.Err()
			},
		})
}

func startManagingK8sIdentities() {
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

	go identityInformer.Run(wait.NeverStop)
}
