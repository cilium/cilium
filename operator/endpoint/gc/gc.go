// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"context"
	"fmt"
	"runtime/pprof"

	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/metrics"
	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type params struct {
	cell.In

	Logger      logrus.FieldLogger
	Lifecycle   hive.Lifecycle
	JobRegistry job.Registry

	Clientset      k8sClient.Clientset
	Pod            resource.Resource[*slim_corev1.Pod]
	CiliumEndpoint resource.Resource[*cilium_api_v2.CiliumEndpoint]
	CiliumNode     resource.Resource[*cilium_api_v2.CiliumNode]

	Metrics Metrics

	Cfg Config
}

type gc struct {
	logger    logrus.FieldLogger
	clientset k8sClient.Clientset

	pod            resource.Resource[*slim_corev1.Pod]
	ciliumEndpoint resource.Resource[*cilium_api_v2.CiliumEndpoint]
	ciliumNode     resource.Resource[*cilium_api_v2.CiliumNode]

	metrics Metrics
}

func registerGC(p params) {
	if !p.Clientset.IsEnabled() {
		return
	}

	gc := &gc{
		logger:         p.Logger,
		clientset:      p.Clientset,
		pod:            p.Pod,
		ciliumEndpoint: p.CiliumEndpoint,
		ciliumNode:     p.CiliumNode,
		metrics:        p.Metrics,
	}

	jobGroup := p.JobRegistry.NewGroup(
		job.WithLogger(p.Logger),
		job.WithPprofLabels(pprof.Labels("cell", "cilium-endpoints-gc")),
	)

	if p.Cfg.CiliumEndpointGCInterval == 0 {
		jobGroup.Add(job.OneShot(
			"cilium-endpoints-one-shot-gc",
			func(ctx context.Context) error {
				return gc.run(ctx, false)
			},
		))
	} else {
		jobGroup.Add(job.Timer(
			"cilium-endpoints-periodic-gc",
			func(ctx context.Context) error {
				return gc.run(ctx, true)
			},
			p.Cfg.CiliumEndpointGCInterval,
		))
	}

	p.Lifecycle.Append(jobGroup)
}

func (gc *gc) run(ctx context.Context, checkOwners bool) error {
	cepStore, err := gc.ciliumEndpoint.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to obtain CiliumEndpoint store: %w", err)
	}

	for _, cep := range cepStore.List() {
		scopedLog := gc.logger.WithFields(logrus.Fields{
			logfields.CEPName:      cep.Name,
			logfields.K8sNamespace: cep.Namespace,
			logfields.EndpointID:   cep.Status.ID,
		})
		scopedLog.Debug("Orphaned CiliumEndpoint is being garbage collected")

		if checkOwners {
			nodeStore, err := gc.ciliumNode.Store(ctx)
			if err != nil {
				return fmt.Errorf("failed to obtain CiliumNode store: %w", err)
			}
			podStore, err := gc.pod.Store(ctx)
			if err != nil {
				return fmt.Errorf("failed to obtain Pod store: %w", err)
			}

			var (
				owner            any
				ownerExists      bool
				checkForPodOwner bool
			)
			for _, ownerRef := range cep.ObjectMeta.OwnerReferences {
				switch ownerRef.Kind {
				case "Pod":
					checkForPodOwner = true

					owner, ownerExists, err = podStore.GetByKey(resource.Key{
						Name:      ownerRef.Name,
						Namespace: cep.Namespace,
					})
					if err != nil {
						scopedLog.WithField(logfields.K8sPodName, ownerRef.Name).WithError(err).Warn("Unable to get Pod from store")
					}
				case cilium_api_v2.CNKindDefinition:
					owner, ownerExists, err = nodeStore.GetByKey(resource.Key{
						Name:      ownerRef.Name,
						Namespace: cep.Namespace,
					})
					if err != nil {
						scopedLog.WithField(logfields.CNName, ownerRef.Name).WithError(err).Warn("Unable to get CiliumNode from store")
					}
				}
				// Stop looking when an existing owner has been found
				if ownerExists {
					break
				}
			}

			if !ownerExists && !checkForPodOwner {
				// Check for a Pod with the same CEP name in case none of the owners existed.
				// This keeps the old behavior even if OwnerReferences are missing
				cepFullName := cep.Namespace + "/" + cep.Name
				owner, ownerExists, err = watchers.PodStore.GetByKey(cepFullName)
				if err != nil {
					scopedLog.WithField(logfields.K8sPodName, cepFullName).WithError(err).Warn("Unable to get pod from store")
				}
			}
			if ownerExists {
				switch ownerObj := owner.(type) {
				case *cilium_api_v2.CiliumNode:
					continue
				case *slim_corev1.Pod:
					// In Kubernetes Jobs, Pods can be left in Kubernetes until the Job
					// is deleted. If the Job is never deleted, Cilium will never receive a Pod
					// delete event, causing the IP to be left in the ipcache.
					// For this reason we should delete the ipcache entries whenever the pod
					// status is either PodFailed or PodSucceeded as it means the IP address
					// is no longer in use.
					if k8sUtils.IsPodRunning(ownerObj.Status) {
						continue
					}
				default:
					scopedLog.WithField(logfields.Object, ownerObj).
						Errorf("Saw %T object while expecting *slim_corev1.Pod or *cilium_api_v2.CiliumNode", ownerObj)
					continue
				}
			}
		}

		PropagationPolicy := meta_v1.DeletePropagationBackground // because these are const strings but the API wants pointers
		err := gc.clientset.CiliumV2().CiliumEndpoints(cep.Namespace).Delete(
			ctx,
			cep.Name,
			meta_v1.DeleteOptions{
				PropagationPolicy: &PropagationPolicy,
				// Set precondition to ensure we are only deleting CEPs owned by the same agent at the time of listing.
				Preconditions: &meta_v1.Preconditions{
					UID: &cep.UID,
				},
			})
		switch {
		case err == nil:
			gc.metrics.EndpointGCObjects.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()
		case k8serrors.IsNotFound(err), k8serrors.IsConflict(err):
			scopedLog.WithError(err).Debug("Unable to delete CEP, will retry again")
		default:
			scopedLog.WithError(err).Warning("Unable to delete orphaned CEP")
			gc.metrics.EndpointGCObjects.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
			return err
		}
	}

	return nil
}
