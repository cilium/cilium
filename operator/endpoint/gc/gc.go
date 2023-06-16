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
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
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

	Metrics Metrics

	Cfg Config
}

type gc struct {
	logger    logrus.FieldLogger
	clientset k8sClient.Clientset

	pod            resource.Resource[*slim_corev1.Pod]
	ciliumEndpoint resource.Resource[*cilium_api_v2.CiliumEndpoint]

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
				return gc.sweep(ctx)
			},
		))
	} else {
		jobGroup.Add(job.Timer(
			"cilium-endpoints-periodic-gc",
			func(ctx context.Context) error {
				// TBC
				return nil
			},
			p.Cfg.CiliumEndpointGCInterval,
		))
	}

	p.Lifecycle.Append(jobGroup)
}

func (gc *gc) sweep(ctx context.Context) error {
	cepStore, err := gc.ciliumEndpoint.Store(ctx)
	if err != nil {
		return fmt.Errorf("failed to obtain CiliumEndpoint store: %w", err)
	}

	for _, cep := range cepStore.List() {
		cepFullName := cep.Namespace + "/" + cep.Name
		scopedLog := gc.logger.WithFields(logrus.Fields{
			logfields.K8sPodName: cepFullName,
			logfields.EndpointID: cep.Status.ID,
		})
		scopedLog.Debug("Orphaned CiliumEndpoint is being garbage collected")

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
