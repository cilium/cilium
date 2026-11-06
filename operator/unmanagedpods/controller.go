// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package unmanagedpods

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/hive/cell"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"

	"github.com/cilium/cilium/pkg/controller"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	minimalPodRestartInterval = 5 * time.Minute
	unmanagedPodMinimalAge    = 30 * time.Second
)

var restartUnmanagedPodsControllerGroup = controller.NewGroup("restart-unmanaged-pods")

type params struct {
	cell.In

	Lifecycle       cell.Lifecycle
	Config          Config
	SharedCfg       SharedConfig
	Clientset       k8sClient.Clientset
	CiliumEndpoints resource.Resource[*cilium_api_v2.CiliumEndpoint]
	Pods            resource.Resource[*slim_corev1.Pod]
	Metrics         *Metrics
	Logger          *slog.Logger
}

func registerController(p params) {
	// Check if the controller is disabled
	if p.Config.UnmanagedPodWatcherInterval == 0 {
		p.Logger.Info("Unmanaged pods controller disabled (interval set to 0)")
		return
	}

	if !p.SharedCfg.K8sEnabled {
		p.Logger.Info("Unmanaged pods controller disabled due to kubernetes support not enabled")
		return
	}

	if p.SharedCfg.DisableCiliumEndpointCRD {
		p.Logger.Info("Unmanaged pods controller disabled as cilium-endpoint-crd is disabled")
		return
	}

	// An empty selector parses to one that matches every pod.
	podRestartSelector, err := labels.Parse(p.Config.PodRestartSelector)
	if err != nil {
		// Not fatal: a malformed selector never matched any pod anyway.
		p.Logger.Error("Unmanaged pods controller disabled due to invalid pod restart selector",
			logfields.Error, err,
			logfields.Selector, p.Config.PodRestartSelector,
		)
		return
	}

	c := &unmanagedPodsController{
		clientset:          p.Clientset,
		ciliumEndpoints:    p.CiliumEndpoints,
		pods:               p.Pods,
		metrics:            p.Metrics,
		logger:             p.Logger,
		interval:           p.Config.UnmanagedPodWatcherInterval,
		podRestartSelector: podRestartSelector,
		lastPodRestart:     map[string]time.Time{},
	}

	p.Lifecycle.Append(cell.Hook{
		OnStart: c.onStart,
		OnStop:  c.onStop,
	})
}

type unmanagedPodsController struct {
	clientset          k8sClient.Clientset
	ciliumEndpoints    resource.Resource[*cilium_api_v2.CiliumEndpoint]
	pods               resource.Resource[*slim_corev1.Pod]
	metrics            *Metrics
	logger             *slog.Logger
	interval           time.Duration
	podRestartSelector labels.Selector
	cepStore           resource.Store[*cilium_api_v2.CiliumEndpoint]
	podStore           resource.Store[*slim_corev1.Pod]
	// lastPodRestart records when each pod, keyed by namespace/name was last restarted.
	lastPodRestart map[string]time.Time

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (c *unmanagedPodsController) onStart(ctx cell.HookContext) error {
	c.ctx, c.cancel = context.WithCancel(context.Background())

	c.wg.Go(func() {
		c.enableUnmanagedController()
	})

	return nil
}

func (c *unmanagedPodsController) onStop(_ cell.HookContext) error {
	c.cancel()
	c.wg.Wait()
	return nil
}

func (c *unmanagedPodsController) enableUnmanagedController() {
	// Reconciling against an unsynced CiliumEndpoint store would make every
	// pod look unmanaged, so wait for the sync before starting the controller.
	cepStore, err := c.ciliumEndpoints.Store(c.ctx)
	if err != nil {
		// Store only fails when the context is cancelled, i.e. on shutdown.
		return
	}
	c.cepStore = cepStore

	podStore, err := c.pods.Store(c.ctx)
	if err != nil {
		return
	}
	c.podStore = podStore

	mgr := controller.NewManager()

	c.wg.Go(func() {
		<-c.ctx.Done()
		mgr.RemoveAllAndWait()
	})

	mgr.UpdateController("restart-unmanaged-pods",
		controller.ControllerParams{
			Group:       restartUnmanagedPodsControllerGroup,
			RunInterval: c.interval,
			DoFunc:      c.reconcile,
		})
}

// podRestartCandidate is an unmanaged pod eligible for restart this cycle.
type podRestartCandidate struct {
	pod *slim_corev1.Pod
	id  string
	age time.Duration
}

// reconcile counts every unmanaged pod, publishes the
// cilium_operator_unmanaged_pods gauge with that full count, and then restarts
// at most one eligible pod. Counting happens before any restart so the gauge
// stays accurate even on cycles where a pod is restarted.
func (c *unmanagedPodsController) reconcile(ctx context.Context) error {
	// Clean up old entries from lastPodRestart map
	for podName, lastRestart := range c.lastPodRestart {
		if time.Since(lastRestart) > 2*minimalPodRestartInterval {
			delete(c.lastPodRestart, podName)
		}
	}

	countUnmanagedPods := 0
	var candidates []*podRestartCandidate

	// The pod store is shared and holds every pod in the cluster, so select
	// the restart candidates here.
	for _, pod := range c.podStore.List() {
		if pod.Status.Phase != slim_corev1.PodRunning || pod.Spec.HostNetwork {
			continue
		}

		if !c.podRestartSelector.Matches(labels.Set(pod.Labels)) {
			continue
		}

		cep, exists, err := c.cepStore.GetByKey(resource.Key{Namespace: pod.Namespace, Name: pod.Name})
		if err != nil {
			c.logger.ErrorContext(ctx,
				"Unexpected error when getting CiliumEndpoint",
				logfields.Error, err,
				logfields.EndpointID, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
			)
			continue
		}

		podID := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
		if exists {
			c.logger.DebugContext(ctx,
				"Found managed pod due to presence of a CEP",
				logfields.K8sPodName, podID,
				logfields.Identity, cep.Status.ID,
			)
			continue
		}

		countUnmanagedPods++
		c.logger.DebugContext(ctx,
			"Found unmanaged pod",
			logfields.K8sPodName, podID,
		)

		if candidate := c.evaluateRestartCandidate(ctx, pod, podID); candidate != nil {
			candidates = append(candidates, candidate)
		}
	}

	// Publish the full count before any restart so the gauge is always accurate.
	c.metrics.UnmanagedPods.Set(float64(countUnmanagedPods))

	// Restart at most one pod per cycle to avoid taking down all replicas at
	// once. On a failed delete, move on to the next candidate so a single
	// failure does not stall progress for the whole cycle.
	for _, candidate := range candidates {
		if c.restartUnmanagedPod(ctx, candidate) {
			break
		}
	}

	return nil
}

// evaluateRestartCandidate returns a candidate if the unmanaged pod is eligible
// for restart (old enough and past its per-pod restart cooldown), else nil.
func (c *unmanagedPodsController) evaluateRestartCandidate(ctx context.Context, pod *slim_corev1.Pod, podID string) *podRestartCandidate {
	startTime := pod.Status.StartTime
	if startTime == nil {
		return nil
	}

	age := time.Since(startTime.Time)
	if age <= unmanagedPodMinimalAge {
		return nil
	}

	if lastRestart, ok := c.lastPodRestart[podID]; ok {
		if timeSinceRestart := time.Since(lastRestart); timeSinceRestart < minimalPodRestartInterval {
			c.logger.DebugContext(ctx,
				"Not restarting unmanaged pod. Not enough time since last restart",
				logfields.TimeSinceRestart, timeSinceRestart,
				logfields.K8sPodName, podID,
			)
			return nil
		}
	}

	return &podRestartCandidate{pod: pod, id: podID, age: age}
}

// restartUnmanagedPod deletes a single unmanaged pod so it is recreated and
// picked up by Cilium. It returns true and records the restart time on success,
// or false if the delete failed (so the caller can try the next candidate).
func (c *unmanagedPodsController) restartUnmanagedPod(ctx context.Context, candidate *podRestartCandidate) bool {
	c.logger.InfoContext(ctx,
		"Restarting unmanaged pod",
		logfields.TimeSincePodStarted, candidate.age,
		logfields.K8sPodName, candidate.id,
	)
	if err := c.clientset.CoreV1().Pods(candidate.pod.Namespace).Delete(ctx, candidate.pod.Name, metav1.DeleteOptions{}); err != nil {
		// Do not emit a warning if the pod has already been deleted (TOCTOU race)
		if !k8sErrors.IsNotFound(err) {
			c.logger.WarnContext(ctx,
				"Unable to restart pod",
				logfields.Error, err,
				logfields.K8sPodName, candidate.id,
			)
		}
		return false
	}
	c.lastPodRestart[candidate.id] = time.Now()
	return true
}
