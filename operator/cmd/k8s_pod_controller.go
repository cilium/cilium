// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/controller"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	minimalPodRestartInterval = 5 * time.Minute
	unmanagedPodMinimalAge    = 30 * time.Second
)

var (
	lastPodRestart = map[string]time.Time{}

	restartUnmanagedPodsControllerGroup = controller.NewGroup("restart-unmanaged-pods")
)

type UnmanagedPodsMetric struct {
	// UnmanagedPods records the pods that are unmanaged by Cilium.
	// This includes Running pods not using hostNetwork, which do not have a corresponding CiliumEndpoint object.
	UnmanagedPods metric.Gauge
}

func NewUnmanagedPodsMetric() *UnmanagedPodsMetric {
	return &UnmanagedPodsMetric{
		UnmanagedPods: metric.NewGauge(
			metric.GaugeOpts{
				Namespace: metrics.CiliumOperatorNamespace,
				Name:      "unmanaged_pods",
				Help:      "The total number of pods observed to be unmanaged by Cilium operator",
			},
		),
	}
}

func enableUnmanagedController(ctx context.Context, logger *slog.Logger, wg *sync.WaitGroup, clientset k8sClient.Clientset, metrics *UnmanagedPodsMetric) {
	// These functions will block until the resources are synced with k8s.
	watchers.CiliumEndpointsInit(ctx, wg, clientset)
	watchers.UnmanagedPodsInit(ctx, wg, clientset)

	mgr := controller.NewManager()

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		mgr.RemoveAllAndWait()
	}()

	mgr.UpdateController("restart-unmanaged-pods",
		controller.ControllerParams{
			Group:       restartUnmanagedPodsControllerGroup,
			RunInterval: time.Duration(operatorOption.Config.UnmanagedPodWatcherInterval) * time.Second,
			DoFunc: func(ctx context.Context) error {
				for podName, lastRestart := range lastPodRestart {
					if time.Since(lastRestart) > 2*minimalPodRestartInterval {
						delete(lastPodRestart, podName)
					}
				}
				countUnmanagedPods := 0
				for _, podItem := range watchers.UnmanagedPodStore.List() {
					pod, ok := podItem.(*slim_corev1.Pod)
					if !ok {
						logger.Error(fmt.Sprintf("unexpected type mapping: found %T, expected %T", pod, &slim_corev1.Pod{}))
						continue
					}
					if pod.Spec.HostNetwork {
						continue
					}
					cep, exists, err := watchers.HasCE(pod.Namespace, pod.Name)
					if err != nil {
						logger.Error(
							"Unexpected error when getting CiliumEndpoint",
							logfields.Error, err,
							logfields.EndpointID, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name),
						)
						continue
					}
					podID := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
					if exists {
						logger.Debug(
							"Found managed pod due to presence of a CEP",
							logfields.Error, err,
							logfields.K8sPodName, podID,
							logfields.Identity, cep.Status.ID,
						)
					} else {
						countUnmanagedPods++
						logger.Debug(
							"Found unmanaged pod",
							logfields.K8sPodName, podID,
						)

						if startTime := pod.Status.StartTime; startTime != nil {
							if age := time.Since((*startTime).Time); age > unmanagedPodMinimalAge {
								if lastRestart, ok := lastPodRestart[podID]; ok {
									if timeSinceRestart := time.Since(lastRestart); timeSinceRestart < minimalPodRestartInterval {
										logger.Debug(
											"Not restarting unmanaged pod. Not enough time since last restart",
											logfields.TimeSinceRestart, timeSinceRestart,
											logfields.K8sPodName, podID,
										)
										continue
									}
								}

								logger.Info(
									"Restarting unmanaged pod",
									logfields.TimeSincePodStarted, age,
									logfields.K8sPodName, podID,
								)
								if err := clientset.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{}); err != nil {
									logger.Warn(
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
				metrics.UnmanagedPods.Set(float64(countUnmanagedPods))
				return nil
			},
		})
}
