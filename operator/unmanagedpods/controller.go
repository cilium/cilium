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
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/controller"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	minimalPodRestartInterval = 5 * time.Minute
	unmanagedPodMinimalAge    = 30 * time.Second
)

var (
	lastPodRestart = map[string]time.Time{}

	restartUnmanagedPodsControllerGroup = controller.NewGroup("restart-unmanaged-pods")
)

type params struct {
	cell.In

	Lifecycle cell.Lifecycle
	Config    Config
	SharedCfg SharedConfig
	Clientset k8sClient.Clientset
	Metrics   *Metrics
	Logger    *slog.Logger
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

	c := &unmanagedPodsController{
		clientset:          p.Clientset,
		metrics:            p.Metrics,
		logger:             p.Logger,
		interval:           p.Config.UnmanagedPodWatcherInterval,
		podRestartSelector: p.Config.PodRestartSelector,
		observeOnly:        p.Config.EnableUnmanagedPodObserveOnly,
	}

	if c.observeOnly {
		p.Logger.Info("Unmanaged pods controller running in observe-only mode: unmanaged pods will be counted and reported via metrics but not restarted")
	}

	p.Lifecycle.Append(cell.Hook{
		OnStart: c.onStart,
		OnStop:  c.onStop,
	})
}

type unmanagedPodsController struct {
	clientset          k8sClient.Clientset
	metrics            *Metrics
	logger             *slog.Logger
	interval           time.Duration
	podRestartSelector string
	observeOnly        bool
	// prevObserveOnlyEligible is the restart-eligible pod count from the last observe-only cycle,
	// used to suppress repeated Info logs when nothing changes.
	prevObserveOnlyEligible int

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
	// These functions will block until the resources are synced with k8s.
	watchers.CiliumEndpointsInit(c.ctx, &c.wg, c.clientset)
	watchers.UnmanagedPodsInit(c.ctx, &c.wg, c.clientset, c.podRestartSelector)

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

// reconcile counts all unmanaged pods, publishes the cilium_operator_unmanaged_pods gauge,
// then deletes at most one restart-eligible pod. Counting precedes deletion so the gauge
// is always accurate, including on cycles where a pod is restarted.
func (c *unmanagedPodsController) reconcile(ctx context.Context) error {
	// Evict stale cooldown entries so the map does not grow unbounded.
	for podName, lastRestart := range lastPodRestart {
		if time.Since(lastRestart) > 2*minimalPodRestartInterval {
			delete(lastPodRestart, podName)
		}
	}

	countUnmanagedPods := 0
	var candidates []*podRestartCandidate

	for _, podItem := range watchers.UnmanagedPodStore.List() {
		pod, ok := podItem.(*slim_corev1.Pod)
		if !ok {
			c.logger.ErrorContext(ctx, fmt.Sprintf("unexpected type mapping: found %T, expected %T", podItem, &slim_corev1.Pod{}))
			continue
		}

		if pod.Spec.HostNetwork {
			continue
		}

		cep, exists, err := watchers.HasCE(pod.Namespace, pod.Name)
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

	// Publish before any deletion so the gauge reflects the true count this cycle.
	c.metrics.UnmanagedPods.Set(float64(countUnmanagedPods))

	if c.observeOnly {
		// Observe-only: log only when the restart-eligible count changes to avoid per-cycle spam.
		// The gauge above already reflects the full unmanaged count every cycle.
		if len(candidates) != c.prevObserveOnlyEligible {
			if len(candidates) > 0 {
				c.logger.InfoContext(ctx,
					fmt.Sprintf("observe-only: %d unmanaged pods, %d eligible for restart (none will be restarted)", countUnmanagedPods, len(candidates)),
				)
			} else if countUnmanagedPods > 0 {
				c.logger.InfoContext(ctx,
					fmt.Sprintf("observe-only: %d unmanaged pods, none eligible for restart yet", countUnmanagedPods),
				)
			} else {
				c.logger.InfoContext(ctx, "observe-only: no unmanaged pods")
			}
			c.prevObserveOnlyEligible = len(candidates)
		}
		for _, candidate := range candidates {
			c.logger.DebugContext(ctx,
				"observe-only: pod eligible for restart",
				logfields.K8sPodName, candidate.id,
				logfields.TimeSincePodStarted, candidate.age,
			)
		}
		return nil
	}

	// Delete at most one pod per cycle to avoid simultaneous restarts.
	// On failure, try the next candidate rather than stalling the cycle.
	for _, candidate := range candidates {
		if c.restartUnmanagedPod(ctx, candidate) {
			break
		}
	}

	return nil
}

// evaluateRestartCandidate returns the pod as a restart candidate if it is old enough
// and past its per-pod cooldown, otherwise nil.
func (c *unmanagedPodsController) evaluateRestartCandidate(ctx context.Context, pod *slim_corev1.Pod, podID string) *podRestartCandidate {
	startTime := pod.Status.StartTime
	if startTime == nil {
		return nil
	}

	age := time.Since(startTime.Time)
	if age <= unmanagedPodMinimalAge {
		return nil
	}

	if lastRestart, ok := lastPodRestart[podID]; ok {
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

// restartUnmanagedPod deletes the pod so it is recreated and picked up by Cilium.
// Returns true on success (restart time recorded), false on failure (caller tries next candidate).
func (c *unmanagedPodsController) restartUnmanagedPod(ctx context.Context, candidate *podRestartCandidate) bool {
	c.logger.InfoContext(ctx,
		"Restarting unmanaged pod",
		logfields.TimeSincePodStarted, candidate.age,
		logfields.K8sPodName, candidate.id,
	)
	if err := c.clientset.CoreV1().Pods(candidate.pod.Namespace).Delete(ctx, candidate.pod.Name, metav1.DeleteOptions{}); err != nil {
		c.logger.WarnContext(ctx,
			"Unable to restart pod",
			logfields.Error, err,
			logfields.K8sPodName, candidate.id,
		)
		return false
	}
	lastPodRestart[candidate.id] = time.Now()
	return true
}
