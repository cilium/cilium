// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"github.com/blang/semver/v4"

	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/pkg/versioncheck"
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
