// Copyright 2016-2018 Authors of Cilium
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
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	unmanagedKubeDnsWatcherInterval int
	unmanagedKubeDnsMinimalAge      = 30 * time.Second
)

func enableUnmanagedKubeDNSController() {
	controller.NewManager().UpdateController("restart-unmanaged-kube-dns",
		controller.ControllerParams{
			RunInterval: time.Duration(unmanagedKubeDnsWatcherInterval) * time.Second,
			DoFunc: func() error {
				pods, err := k8s.Client().CoreV1().Pods("").List(metav1.ListOptions{
					LabelSelector: "k8s-app=kube-dns",
					FieldSelector: "status.phase=Running",
				})
				if err != nil {
					return err
				}

				for _, pod := range pods.Items {
					id, podHasIdentity := pod.Annotations[ciliumio.CiliumK8sAnnotationPrefix+"identity"]
					if podHasIdentity {
						log.Debugf("Found kube-dns pod %s/%s with identity %s", pod.Namespace, pod.Name, id)
					} else {
						log.Debugf("Found unmanaged kube-dns pod %s/%s", pod.Namespace, pod.Name)
						if startTime := pod.Status.StartTime; startTime != nil {
							if age := time.Since((*startTime).Time); age > unmanagedKubeDnsMinimalAge {
								log.Infof("Restarting unmanaged kube-dns pod %s/%s started %s ago", pod.Namespace, pod.Name, age)
								if err := k8s.Client().CoreV1().Pods(pod.Namespace).Delete(pod.Name, &metav1.DeleteOptions{}); err != nil {
									log.WithError(err).Warningf("Unable to restart pod %s/%s", pod.Namespace, pod.Name)
								}
							}
						}
					}
				}

				return nil
			},
		})
}
