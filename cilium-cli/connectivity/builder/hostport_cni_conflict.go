// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/defaults"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/tests"
)

type hostPortCNIConflict struct{}

func (hostPortCNIConflict) build(ct *check.ConnectivityTest, _ map[string]string) {
	newTest("hostport-cni-conflict", ct).
		WithCondition(func() bool {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cm, err := ct.K8sClient().GetConfigMap(ctx, ct.Params().CiliumNamespace,
				defaults.ConfigMapName, metav1.GetOptions{})
			if err != nil || cm.Data["kube-proxy-replacement"] != "true" ||
				cm.Data["cni-check-host-port-conflict"] != "true" {
				return false
			}
			return tests.HostPortListenerAvailable(ctx, ct)
		}, fmt.Sprintf("KPR or HostPort conflict checking is disabled, or no node has a wildcard TCP/%d listener", tests.HostPortConflictPort)).
		WithScenarios(tests.HostPortConflict())
}
