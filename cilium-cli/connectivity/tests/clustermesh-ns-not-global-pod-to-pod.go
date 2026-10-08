// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

func ClusterMeshNSNotGlobalPodToPod(ns string) check.Scenario {
	return &clusterMeshNSNotGlobalPodToPod{
		ScenarioBase: check.NewScenarioBase(),
		ns:           ns,
	}
}

type clusterMeshNSNotGlobalPodToPod struct {
	check.ScenarioBase
	ns string
}

func (s *clusterMeshNSNotGlobalPodToPod) Name() string {
	return "clustermesh-ns-not-global-pod-to-pod"
}

func (s *clusterMeshNSNotGlobalPodToPod) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	clients := ct.Clients()
	if len(clients) < 2 {
		t.Fatalf("non-global namespace pod-to-pod test requires at least 2 clusters")
	}
	localClient, remoteClient := clients[0], clients[1]

	clientPod := s.findPod(ctx, t, localClient, check.NonGlobalClientName)
	serverPod := s.findPod(ctx, t, remoteClient, check.NonGlobalServerName)

	src := check.NewPod(localClient, clientPod, "http", "/", 0)
	dst := check.NewPod(remoteClient, serverPod, "http", "/", check.NonGlobalPort)

	t.ForEachIPFamily(func(ipFam features.IPFamily) {
		t.NewAction(s, fmt.Sprintf("curl-%s", ipFam), &src, &dst, ipFam).Run(func(a *check.Action) {
			a.ExecInPod(ctx, a.CurlCommand(&dst))
		})
	})
}

func (s *clusterMeshNSNotGlobalPodToPod) findPod(ctx context.Context, t *check.Test, client *k8s.Client, name string) *corev1.Pod {
	pods, err := client.ListPods(ctx, s.ns, metav1.ListOptions{LabelSelector: "name=" + name})
	if err != nil {
		t.Fatalf("unable to list pods %s in namespace %s/%s: %v", name, client.ClusterName(), s.ns, err)
	}
	if len(pods.Items) == 0 {
		t.Fatalf("no pod %s found in namespace %s/%s", name, client.ClusterName(), s.ns)
	}
	return pods.Items[0].DeepCopy()
}
