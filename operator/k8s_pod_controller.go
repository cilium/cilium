// Copyright 2016-2019 Authors of Cilium
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

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	minimalPodRestartInterval = 5 * time.Minute
)

var (
	unmanagedKubeDnsWatcherInterval int
	unmanagedKubeDnsMinimalAge      = 30 * time.Second
	lastPodRestart                  = map[string]time.Time{}
)

func enableUnmanagedKubeDNSController() {
	controller.NewManager().UpdateController("restart-unmanaged-kube-dns",
		controller.ControllerParams{
			RunInterval: time.Duration(unmanagedKubeDnsWatcherInterval) * time.Second,
			DoFunc: func(ctx context.Context) error {
				for podName, lastRestart := range lastPodRestart {
					if time.Since(lastRestart) > 2*minimalPodRestartInterval {
						delete(lastPodRestart, podName)
					}
				}

				pods, err := k8s.Client().CoreV1().Pods("").List(metav1.ListOptions{
					LabelSelector: "k8s-app=kube-dns",
					FieldSelector: "status.phase=Running",
				})
				if err != nil {
					return err
				}

				for _, pod := range pods.Items {
					if pod.Spec.HostNetwork {
						continue
					}
					cep, err := ciliumK8sClient.CiliumV2().CiliumEndpoints(pod.Namespace).Get(pod.Name, metav1.GetOptions{})
					podID := fmt.Sprintf("%s/%s", pod.Namespace, pod.Name)
					switch {
					case err == nil:
						log.Debugf("Found kube-dns pod %s with identity %d", podID, cep.Status.ID)
					case errors.IsNotFound(err):
						log.Debugf("Found unmanaged kube-dns pod %s", podID)
						if startTime := pod.Status.StartTime; startTime != nil {
							if age := time.Since((*startTime).Time); age > unmanagedKubeDnsMinimalAge {
								if lastRestart, ok := lastPodRestart[podID]; ok {
									if timeSinceRestart := time.Since(lastRestart); timeSinceRestart < minimalPodRestartInterval {
										log.Debugf("Not restaring %s, only %s since last restart", podID, timeSinceRestart)
										continue
									}
								}

								log.Infof("Restarting unmanaged kube-dns pod %s started %s ago", podID, age)
								if err := k8s.Client().CoreV1().Pods(pod.Namespace).Delete(pod.Name, &metav1.DeleteOptions{}); err != nil {
									log.WithError(err).Warningf("Unable to restart pod %s", podID)
								} else {
									lastPodRestart[podID] = time.Now()
								}

							}
						}
					default:
						return err
					}
				}

				return nil
			},
		})
}
