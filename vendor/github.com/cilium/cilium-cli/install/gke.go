// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"fmt"
	"strings"
)

func (k *K8sInstaller) gkeNativeRoutingCIDR(contextName string) (string, error) {
	// Example: gke_cilium-dev_us-west2-a_tgraf-cluster1
	parts := strings.Split(contextName, "_")
	if len(parts) < 4 {
		return "", fmt.Errorf("unable to derive region and zone from context name %q: not in the form gke_PROJECT_ZONE_NAME", contextName)
	}

	bytes, err := k.Exec("gcloud", "container", "clusters", "describe", parts[3], "--zone", parts[2], "--format", "value(clusterIpv4Cidr)")
	if err != nil {
		return "", err
	}

	cidr := strings.TrimSuffix(string(bytes), "\n")
	k.Log("✅ Detected GKE native routing CIDR: %s", cidr)

	return cidr, nil
}
