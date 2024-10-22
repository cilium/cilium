// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
)

// IsLocalCiliumNode returns true if the given CiliumNode object refers to the
// CiliumNode object representing the local node.
func IsLocalCiliumNode(n *ciliumv2.CiliumNode) bool {
	return n != nil && n.GetName() == nodeTypes.GetName()
}
