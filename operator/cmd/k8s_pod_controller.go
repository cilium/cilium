// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	operatorOption "github.com/cilium/cilium/operator/option"
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
)

func enableUnmanagedController(ctx context.Context, wg *sync.WaitGroup, clientset k8sClient.Clientset) {
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
			RunInterval: time.Duration(operatorOption.Config.UnmanagedPodWatcherInterval) * time.Second,
			DoFunc: func(ctx context.Context) error {
				for podName, lastRestart := range lastPodRestart {
					if time.Since(lastRestart) > 2*minimalPodRestartInterval {
						delete(lastPodRestart, podName)
					}
				}
				for _, podItem := range watchers.UnmanagedPodStore.List() {
					pod, ok := podItem.(*slim_corev1.Pod)
					if !ok {
						log.Errorf("unexpected type mapping: found %T, expected %T", pod, &slim_corev1.Pod{})
						continue
					}
					if pod.Spec.HostNetwork {
						continue
					}
					cep, exists, err := watchers.HasCE(pod.Namespace, pod.Name)
					if err != nil {
						log.WithError(err).WithField(logfields.EndpointID, fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)).
							Errorf("Unexpected error when getting CiliumEndpoint")
						continue
					}
					podID := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
					if exists {
						log.WithFields(logrus.Fields{
							logfields.K8sPodName: podID,
							logfields.Identity:   cep.Status.ID,
						}).Debug("Found managed pod due to presence of a CEP")
					} else {
						log.WithField(logfields.K8sPodName, podID).Debugf("Found unmanaged pod")
						if startTime := pod.Status.StartTime; startTime != nil {
							if age := time.Since((*startTime).Time); age > unmanagedPodMinimalAge {
								if lastRestart, ok := lastPodRestart[podID]; ok {
									if timeSinceRestart := time.Since(lastRestart); timeSinceRestart < minimalPodRestartInterval {
										log.WithField(logfields.K8sPodName, podID).
											Debugf("Not restarting unmanaged pod, only %s since last restart", timeSinceRestart)
										continue
									}
								}

								log.WithField(logfields.K8sPodName, podID).Infof("Restarting unmanaged pod, started %s ago", age)
								if err := clientset.CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{}); err != nil {
									log.WithError(err).WithField(logfields.K8sPodName, podID).Warning("Unable to restart pod")
								} else {
									lastPodRestart[podID] = time.Now()

									// Delete a single pod per iteration to avoid killing all replicas at once
									return nil
								}

							}
						}
					}
				}

				return nil
			},
		})
}
