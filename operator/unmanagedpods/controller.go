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
	if p.Config.Interval == 0 {
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
		clientset: p.Clientset,
		metrics:   p.Metrics,
		logger:    p.Logger,
		interval:  p.Config.Interval,
	}

	p.Lifecycle.Append(cell.Hook{
		OnStart: c.onStart,
		OnStop:  c.onStop,
	})
}

type unmanagedPodsController struct {
	clientset k8sClient.Clientset
	metrics   *Metrics
	logger    *slog.Logger
	interval  time.Duration

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (c *unmanagedPodsController) onStart(ctx cell.HookContext) error {
	c.ctx, c.cancel = context.WithCancel(context.Background())

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.enableUnmanagedController()
	}()

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
	watchers.UnmanagedPodsInit(c.ctx, &c.wg, c.clientset)

	mgr := controller.NewManager()

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		<-c.ctx.Done()
		mgr.RemoveAllAndWait()
	}()

	mgr.UpdateController("restart-unmanaged-pods",
		controller.ControllerParams{
			Group:       restartUnmanagedPodsControllerGroup,
			RunInterval: c.interval,
			DoFunc: func(ctx context.Context) error {
				// Clean up old entries from lastPodRestart map
				for podName, lastRestart := range lastPodRestart {
					if time.Since(lastRestart) > 2*minimalPodRestartInterval {
						delete(lastPodRestart, podName)
					}
				}

				countUnmanagedPods := 0
				for _, podItem := range watchers.UnmanagedPodStore.List() {
					pod, ok := podItem.(*slim_corev1.Pod)
					if !ok {
						c.logger.ErrorContext(ctx, fmt.Sprintf("unexpected type mapping: found %T, expected %T", pod, &slim_corev1.Pod{}))
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
							logfields.Error, err,
							logfields.K8sPodName, podID,
							logfields.Identity, cep.Status.ID,
						)
					} else {
						countUnmanagedPods++
						c.logger.DebugContext(ctx,
							"Found unmanaged pod",
							logfields.K8sPodName, podID,
						)

						if startTime := pod.Status.StartTime; startTime != nil {
							if age := time.Since((*startTime).Time); age > unmanagedPodMinimalAge {
								if lastRestart, ok := lastPodRestart[podID]; ok {
									if timeSinceRestart := time.Since(lastRestart); timeSinceRestart < minimalPodRestartInterval {
										c.logger.DebugContext(ctx,
											"Not restarting unmanaged pod. Not enough time since last restart",
											logfields.TimeSinceRestart, timeSinceRestart,
											logfields.K8sPodName, podID,
										)
										continue
									}
								}

								c.logger.InfoContext(ctx,
									"Restarting unmanaged pod",
									logfields.TimeSincePodStarted, age,
									logfields.K8sPodName, podID,
								)
								if err := c.clientset.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{}); err != nil {
									c.logger.WarnContext(ctx,
										"Unable to restart pod",
										logfields.Error, err,
										logfields.K8sPodName, podID,
									)
								} else {
									lastPodRestart[podID] = time.Now()

									// Delete a single pod per iteration to avoid killing all replicas at once
									return nil
								}
							}
						}
					}
				}

				c.metrics.UnmanagedPods.Set(float64(countUnmanagedPods))
				return nil
			},
		})
}
