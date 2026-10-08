/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package kubernetes

import (
	"context"
	"io"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	clientset "k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// DumpEchoLogs returns logs of the echoserver pod in
// in the given namespace and with the given name.
func DumpEchoLogs(ctx context.Context, ns, name string, c client.Client, cs clientset.Interface, since time.Time) ([]string, error) {
	var logs []string

	pods := new(corev1.PodList)
	podListOptions := &client.ListOptions{
		LabelSelector: labels.SelectorFromSet(map[string]string{"app": name}),
		Namespace:     ns,
	}
	if err := c.List(ctx, pods, podListOptions); err != nil {
		return nil, err
	}

	podLogOptions := &corev1.PodLogOptions{
		Container: name,
		SinceTime: &v1.Time{Time: since},
	}
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodFailed {
			continue
		}
		podLogs, err := dumpPodLogs(ctx, cs, ns, pod.Name, podLogOptions)
		if err != nil {
			continue
		}
		logs = append(logs, podLogs...)
	}

	return logs, nil
}

func dumpPodLogs(ctx context.Context, cs clientset.Interface, ns, podName string, podLogOptions *corev1.PodLogOptions) ([]string, error) {
	req := cs.CoreV1().Pods(ns).GetLogs(podName, podLogOptions)
	logStream, err := req.Stream(ctx)
	if err != nil {
		return nil, err
	}
	defer logStream.Close()

	logBytes, err := io.ReadAll(logStream)
	if err != nil {
		return nil, err
	}

	return strings.Split(string(logBytes), "\n"), nil
}
