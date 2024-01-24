// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointgc

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/hive/cell"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sconstv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// params contains all the dependencies for the endpoint-gc.
// They will be provided through dependency injection.
type params struct {
	cell.In

	Logger    logrus.FieldLogger
	Lifecycle cell.Lifecycle

	Clientset       k8sClient.Clientset
	CiliumEndpoints resource.Resource[*cilium_api_v2.CiliumEndpoint]
	CiliumNodes     resource.Resource[*cilium_api_v2.CiliumNode]
	Pods            resource.Resource[*slim_corev1.Pod]

	SharedCfg SharedConfig

	Metrics *Metrics
}

// GC represents the Cilium endpoints periodic and one-off GC.
type GC struct {
	logger logrus.FieldLogger

	once     bool
	interval time.Duration

	clientset       k8sClient.Clientset
	ciliumEndpoints resource.Resource[*cilium_api_v2.CiliumEndpoint]
	ciliumNodes     resource.Resource[*cilium_api_v2.CiliumNode]
	pods            resource.Resource[*slim_corev1.Pod]

	mgr *controller.Manager

	metrics *Metrics
}

func registerGC(p params) {
	if !p.Clientset.IsEnabled() {
		return
	}

	once := p.SharedCfg.Interval == 0 || p.SharedCfg.DisableCiliumEndpointCRD

	gc := &GC{
		logger:          p.Logger,
		interval:        p.SharedCfg.Interval,
		once:            once,
		clientset:       p.Clientset,
		ciliumEndpoints: p.CiliumEndpoints,
		ciliumNodes:     p.CiliumNodes,
		pods:            p.Pods,
		metrics:         p.Metrics,
	}
	p.Lifecycle.Append(gc)
}

func (g *GC) Start(ctx cell.HookContext) error {
	if g.once {
		if !g.checkForCiliumEndpointCRD(ctx) {
			// CEP GC set to once and CRD is not present, NOT starting GC
			return nil
		}
		g.interval = 0
		g.logger.Info("Running the garbage collector only once to clean up leftover CiliumEndpoint custom resources")
	} else {
		g.logger.Info("Starting to garbage collect stale CiliumEndpoint custom resources")
	}

	g.mgr = controller.NewManager()
	g.mgr.UpdateController("to-k8s-ciliumendpoint-gc",
		controller.ControllerParams{
			Group:       controller.NewGroup("to-k8s-ciliumendpoint-gc"),
			RunInterval: g.interval,
			DoFunc:      g.doGC,
		})

	return nil
}

func (g *GC) Stop(ctx cell.HookContext) error {
	if g.mgr != nil {
		g.mgr.RemoveAllAndWait()
	}
	return nil
}

func (g *GC) checkForCiliumEndpointCRD(ctx cell.HookContext) bool {
	_, err := g.clientset.ApiextensionsV1().CustomResourceDefinitions().Get(
		ctx, k8sconstv2.CEPName, metav1.GetOptions{ResourceVersion: "0"},
	)
	if err == nil {
		return true
	} else if k8sErrors.IsNotFound(err) {
		g.logger.WithError(err).Info("CiliumEndpoint CRD cannot be found, skipping garbage collection")
	} else {
		g.logger.WithError(err).Error(
			"Unable to determine if CiliumEndpoint CRD is installed, cannot start garbage collector",
		)
	}
	return false
}

func (g *GC) doGC(ctx context.Context) error {
	cepStore, err := g.ciliumEndpoints.Store(ctx)
	if err != nil {
		g.logger.WithError(err).Error("Couldn't get CEP Store")
		return err
	}
	// For each CEP we fetched, check if we know about it
	for _, cep := range cepStore.List() {
		scopedLog := g.logger.WithFields(logrus.Fields{
			logfields.K8sPodName: cep.Namespace + "/" + cep.Name,
		})

		if !g.checkIfCEPShouldBeDeleted(cep, scopedLog, ctx) {
			continue
		}
		// FIXME: this is fragile as we might have received the
		// CEP notification first but not the pod notification
		// so we need to have a similar mechanism that we have
		// for the keep alive of security identities.
		err = g.deleteCEP(cep, scopedLog, ctx)
		if err != nil {
			return err
		}
	}
	return nil
}

type deleteCheckResult struct {
	shouldBeDeleted bool
	validated       bool
}

func (g *GC) checkIfCEPShouldBeDeleted(cep *cilium_api_v2.CiliumEndpoint, scopedLog *logrus.Entry, ctx context.Context) bool {
	if g.once {
		// If we are running this function "once" it means that we
		// will delete all CEPs in the cluster regardless of the pod
		// state.
		return true
	}
	var podStore resource.Store[*slim_corev1.Pod]
	var ciliumNodeStore resource.Store[*cilium_api_v2.CiliumNode]
	var err error
	podChecked := false
	podStore, err = g.pods.Store(ctx)
	if err != nil {
		scopedLog.WithError(err).Warn("Unable to get pod store")
		return false
	}
	ciliumNodeStore, err = g.ciliumNodes.Store(ctx)
	if err != nil {
		scopedLog.WithError(err).Warn("Unable to get cilium node store")
		return false
	}

	for _, owner := range cep.ObjectMeta.OwnerReferences {
		switch owner.Kind {
		case "Pod":
			result := g.checkPodForCEP(resource.Key{Name: owner.Name, Namespace: cep.Namespace}, podStore, scopedLog)
			if result.validated {
				return result.shouldBeDeleted
			}
			podChecked = true
		case "CiliumNode":
			result := g.checkCiliumNodeForCEP(resource.Key{Name: owner.Name}, ciliumNodeStore, scopedLog)
			if result.validated {
				return result.shouldBeDeleted
			}
		}
	}
	if !podChecked {
		// Check for a Pod in case none of the owners existed
		// This keeps the old behavior even if OwnerReferences are missing
		result := g.checkPodForCEP(
			resource.Key{Name: cep.Name, Namespace: cep.Namespace}, podStore, scopedLog)
		if result.validated {
			return result.shouldBeDeleted
		}
	}
	return true
}

func (g *GC) checkPodForCEP(key resource.Key, podStore resource.Store[*slim_corev1.Pod], scopedLog *logrus.Entry) deleteCheckResult {
	pod, exists, err := podStore.GetByKey(key)
	if err != nil {
		scopedLog.WithError(err).Warn("Unable to get pod from store")
	}
	if !exists {
		return deleteCheckResult{validated: false}
	}
	// In Kubernetes Jobs, Pods can be left in Kubernetes until the Job
	// is deleted. If the Job is never deleted, Cilium will never receive a Pod
	// delete event, causing the IP to be left in the ipcache.
	// For this reason we should delete the ipcache entries whenever the pod
	// status is either PodFailed or PodSucceeded as it means the IP address
	// is no longer in use.
	if k8sUtils.IsPodRunning(pod.Status) {
		return deleteCheckResult{validated: true, shouldBeDeleted: false}
	}
	return deleteCheckResult{validated: true, shouldBeDeleted: true}
}

func (g *GC) checkCiliumNodeForCEP(key resource.Key, ciliumNodeStore resource.Store[*cilium_api_v2.CiliumNode], scopedLog *logrus.Entry) deleteCheckResult {
	_, exists, err := ciliumNodeStore.GetByKey(key)
	if err != nil {
		scopedLog.WithError(err).Warn("Unable to get CiliumNode from store")
	}
	if !exists {
		return deleteCheckResult{validated: false}
	}
	return deleteCheckResult{validated: true, shouldBeDeleted: false}
}

func (g *GC) deleteCEP(cep *cilium_api_v2.CiliumEndpoint, scopedLog *logrus.Entry, ctx context.Context) error {
	ciliumClient := g.clientset.CiliumV2()
	scopedLog = scopedLog.WithFields(logrus.Fields{
		logfields.EndpointID: cep.Status.ID,
	})
	scopedLog.Debug("Orphaned CiliumEndpoint is being garbage collected")
	propagationPolicy := meta_v1.DeletePropagationBackground // because these are const strings but the API wants pointers
	err := ciliumClient.CiliumEndpoints(cep.Namespace).Delete(
		ctx,
		cep.Name,
		meta_v1.DeleteOptions{
			PropagationPolicy: &propagationPolicy,
			// Set precondition to ensure we are only deleting CEPs owned by
			// this agent.
			Preconditions: &meta_v1.Preconditions{
				UID: &cep.UID,
			},
		})
	switch {
	case err == nil:
		g.metrics.EndpointGCObjects.WithLabelValues(LabelValueOutcomeSuccess).Inc()
	case k8serrors.IsNotFound(err), k8serrors.IsConflict(err):
		scopedLog.WithError(err).Debug("Unable to delete CEP, will retry again")
	default:
		scopedLog.WithError(err).Warning("Unable to delete orphaned CEP")
		g.metrics.EndpointGCObjects.WithLabelValues(LabelValueOutcomeFail).Inc()
		return err
	}
	return nil
}
