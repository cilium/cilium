// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"github.com/blang/semver/v4"
	appsv1 "k8s.io/api/apps/v1"

	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/cilium/cilium-cli/internal/utils"
	"github.com/cilium/cilium-cli/k8s"
)

func needsNodeInit(k k8s.Kind, version semver.Version) bool {
	switch k {

	case k8s.KindAKS, k8s.KindGKE:
		return true
	case k8s.KindEKS:
		if versioncheck.MustCompile("<=1.13.1")(version) {
			return true
		}
	}
	return false
}

func (k *K8sInstaller) generateNodeInitDaemonSet(_ k8s.Kind) *appsv1.DaemonSet {
	var (
		dsFileName string
	)

	switch {
	case versioncheck.MustCompile(">1.10.99")(k.chartVersion):
		dsFileName = "templates/cilium-nodeinit/daemonset.yaml"
	case versioncheck.MustCompile(">=1.9.0")(k.chartVersion):
		dsFileName = "templates/cilium-nodeinit-daemonset.yaml"
	}

	dsFile := k.manifests[dsFileName]

	var ds appsv1.DaemonSet
	utils.MustUnmarshalYAML([]byte(dsFile), &ds)
	return &ds
}
