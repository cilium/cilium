// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/controller"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// enableCiliumEndpointSyncGC starts the node-singleton sweeper for
// CiliumEndpoint objects where the managing node is no longer running. These
// objects are created by the sync-to-k8s-ciliumendpoint controller on each
// Endpoint.
// The general steps are:
//   - list all CEPs in the cluster
//   - for each CEP
//     delete CEP if the corresponding pod does not exist
//
// CiliumEndpoint objects have the same name as the pod they represent
func enableCiliumEndpointSyncGC(ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset, cns *ciliumNodeSynchronizer, once bool) {
	var (
		controllerName = "to-k8s-ciliumendpoint-gc"
		scopedLog      = log.WithField("controller", controllerName)
		gcInterval     time.Duration
	)
	ctx, cancel := context.WithCancel(ctx)

	if once {
		log.Info("Running the garbage collector only once to clean up leftover CiliumEndpoint custom resources")
		gcInterval = 0
	} else {
		log.Info("Starting to garbage collect stale CiliumEndpoint custom resources")
		gcInterval = operatorOption.Config.EndpointGCInterval
	}

	// This functions will block until the resources are synced with k8s.
	watchers.CiliumEndpointsInit(ctx, wg, clientset)
	if !once {
		// If we are running this function "once" it means that we
		// will delete all CEPs in the cluster regardless of the pod
		// state.
		watchers.PodsInit(ctx, wg, clientset)
	}
	<-cns.k8sCiliumNodesCacheSynced

	// this dummy manager is needed only to add this controller to the global list
	mgr := controller.NewManager()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		mgr.RemoveAllAndWait()
	}()

	mgr.UpdateController(controllerName,
		controller.ControllerParams{
			RunInterval: gcInterval,
			DoFunc: func(ctx context.Context) error {
				return doCiliumEndpointSyncGC(ctx, clientset, cns, once, cancel, scopedLog)
			},
		})
}

func doCiliumEndpointSyncGC(ctx context.Context, clientset k8sClient.Clientset, cns *ciliumNodeSynchronizer, once bool, cancel context.CancelFunc, scopedLog *logrus.Entry) error {
	ciliumClient := clientset.CiliumV2()
	// For each CEP we fetched, check if we know about it
	for _, cepObj := range watchers.CiliumEndpointStore.List() {
		cep, ok := cepObj.(*cilium_v2.CiliumEndpoint)
		if !ok {
			log.WithField(logfields.Object, cepObj).
				Errorf("Saw %T object while expecting *cilium_v2.CiliumEndpoint", cepObj)
			continue
		}
		cepFullName := cep.Namespace + "/" + cep.Name
		scopedLog = scopedLog.WithFields(logrus.Fields{
			logfields.K8sPodName: cepFullName,
		})

		// If we are running this function "once" it means that we
		// will delete all CEPs in the cluster regardless of the pod
		// state therefore we won't even watch for the pod store.
		if !once {
			var podObj interface{}
			var err error
			exists := false
			podChecked := false
			for _, owner := range cep.ObjectMeta.OwnerReferences {
				switch owner.Kind {
				case "Pod":
					podObj, exists, err = watchers.PodStore.GetByKey(cepFullName)
					if err != nil {
						scopedLog.WithError(err).Warn("Unable to get pod from store")
					}
					podChecked = true
				case "CiliumNode":
					podObj, exists, err = cns.ciliumNodeStore.GetByKey(owner.Name)
					if err != nil {
						scopedLog.WithError(err).Warn("Unable to get CiliumNode from store")
					}
				}
				// Stop looking when an existing owner has been found
				if exists {
					break
				}
			}
			if !exists && !podChecked {
				// Check for a Pod in case none of the owners existed
				// This keeps the old behavior even if OwnerReferences are missing
				podObj, exists, err = watchers.PodStore.GetByKey(cepFullName)
				if err != nil {
					scopedLog.WithError(err).Warn("Unable to get pod from store")
				}
			}
			if exists {
				switch pod := podObj.(type) {
				case *cilium_v2.CiliumNode:
					continue
				case *slim_corev1.Pod:
					// In Kubernetes Jobs, Pods can be left in Kubernetes until the Job
					// is deleted. If the Job is never deleted, Cilium will never receive a Pod
					// delete event, causing the IP to be left in the ipcache.
					// For this reason we should delete the ipcache entries whenever the pod
					// status is either PodFailed or PodSucceeded as it means the IP address
					// is no longer in use.
					if k8sUtils.IsPodRunning(pod.Status) {
						continue
					}
				default:
					log.WithField(logfields.Object, podObj).
						Errorf("Saw %T object while expecting *slim_corev1.Pod or *cilium_v2.CiliumNode", podObj)
					continue
				}
			}
		}
		// FIXME: this is fragile as we might have received the
		// CEP notification first but not the pod notification
		// so we need to have a similar mechanism that we have
		// for the keep alive of security identities.
		scopedLog = scopedLog.WithFields(logrus.Fields{
			logfields.EndpointID: cep.Status.ID,
		})
		scopedLog.Debug("Orphaned CiliumEndpoint is being garbage collected")
		PropagationPolicy := meta_v1.DeletePropagationBackground // because these are const strings but the API wants pointers
		err := ciliumClient.CiliumEndpoints(cep.Namespace).Delete(
			ctx,
			cep.Name,
			meta_v1.DeleteOptions{
				PropagationPolicy: &PropagationPolicy,
				// Set precondition to ensure we are only deleting CEPs owned by
				// this agent.
				Preconditions: &meta_v1.Preconditions{
					UID: &cep.UID,
				},
			})
		switch {
		case err == nil:
			successfulEndpointObjectGC()
		case k8serrors.IsNotFound(err), k8serrors.IsConflict(err):
			scopedLog.WithError(err).Debug("Unable to delete CEP, will retry again")
		default:
			scopedLog.WithError(err).Warning("Unable to delete orphaned CEP")
			failedEndpointObjectGC()
			return err
		}
	}
	// We have cleaned up all CEPs from Kubernetes so we can stop
	// the k8s watchers.
	if once {
		cancel()
	}
	return nil
}

func successfulEndpointObjectGC() {
	if operatorOption.Config.EnableMetrics {
		metrics.EndpointGCObjects.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
	}
}

func failedEndpointObjectGC() {
	if operatorOption.Config.EnableMetrics {
		metrics.EndpointGCObjects.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
	}
}
