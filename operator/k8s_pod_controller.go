// Copyright 2016-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"time"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
)

const (
	minimalPodRestartInterval  = 5 * time.Minute
	unmanagedKubeDnsMinimalAge = 30 * time.Second
)

var (
	lastPodRestart = map[string]time.Time{}
)

func enableUnmanagedKubeDNSController() {
	// These functions will block until the resources are synced with k8s.
	watchers.CiliumEndpointsInit(k8s.CiliumClient().CiliumV2(), wait.NeverStop)
	watchers.UnmanagedKubeDNSPodsInit(k8s.WatcherClient())

	controller.NewManager().UpdateController("restart-unmanaged-kube-dns",
		controller.ControllerParams{
			RunInterval: time.Duration(operatorOption.Config.UnmanagedPodWatcherInterval) * time.Second,
			DoFunc: func(ctx context.Context) error {
				for podName, lastRestart := range lastPodRestart {
					if time.Since(lastRestart) > 2*minimalPodRestartInterval {
						delete(lastPodRestart, podName)
					}
				}
				for _, podItem := range watchers.UnmanagedKubeDNSPodStore.List() {
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
						}).Debug("Found kube-dns pod")
					} else {
						log.WithField(logfields.K8sPodName, podID).Debugf("Found unmanaged kube-dns pod")
						if startTime := pod.Status.StartTime; startTime != nil {
							if age := time.Since((*startTime).Time); age > unmanagedKubeDnsMinimalAge {
								if lastRestart, ok := lastPodRestart[podID]; ok {
									if timeSinceRestart := time.Since(lastRestart); timeSinceRestart < minimalPodRestartInterval {
										log.WithField(logfields.K8sPodName, podID).
											Debugf("Not restaring kube-dns pod, only %s since last restart", timeSinceRestart)
										continue
									}
								}

								log.WithField(logfields.K8sPodName, podID).Infof("Restarting unmanaged kube-dns pod, started %s ago", age)
								if err := k8s.Client().CoreV1().Pods(pod.Namespace).Delete(ctx, pod.Name, metav1.DeleteOptions{}); err != nil {
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
