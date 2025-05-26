// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package install

import (
	"github.com/cilium/cilium/cilium-cli/k8s"
)

func needsNodeInit(k k8s.Kind) bool {
	return k == k8s.KindAKS || k == k8s.KindGKE
}
