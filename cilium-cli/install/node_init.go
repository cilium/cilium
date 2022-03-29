// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package install

import (
	"github.com/cilium/cilium/pkg/versioncheck"
	appsv1 "k8s.io/api/apps/v1"

	"github.com/cilium/cilium-cli/internal/k8s"
	"github.com/cilium/cilium-cli/internal/utils"
)

var (
	nodeInitScript = map[k8s.Kind]string{
		k8s.KindEKS: "",
		k8s.KindGKE: "",
	}
)

func (k *K8sInstaller) generateNodeInitDaemonSet(_ k8s.Kind) *appsv1.DaemonSet {
	var (
		dsFileName string
	)

	ciliumVer := k.getCiliumVersion()
	switch {
	case versioncheck.MustCompile(">1.10.99")(ciliumVer):
		dsFileName = "templates/cilium-nodeinit/daemonset.yaml"
	case versioncheck.MustCompile(">=1.9.0")(ciliumVer):
		dsFileName = "templates/cilium-nodeinit-daemonset.yaml"
	}

	dsFile := k.manifests[dsFileName]

	var ds appsv1.DaemonSet
	utils.MustUnmarshalYAML([]byte(dsFile), &ds)
	return &ds
}
