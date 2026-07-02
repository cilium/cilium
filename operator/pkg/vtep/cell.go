// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"github.com/cilium/hive/cell"
)

// Cell is the VTEP operator control plane. It watches cluster-scoped
// CiliumVTEPConfig objects and CiliumNodes, evaluates each config's nodeSelector
// against every node, resolves the per-node set of VTEP endpoints (detecting
// CIDR conflicts), and writes the result into one CiliumVTEPNodeConfig per node
// (metadata.name == node name). This mirrors the CiliumBGPClusterConfig ->
// CiliumBGPNodeConfig operator pattern.
var Cell = cell.Module(
	"vtep-operator",
	"VTEP Operator resolves CiliumVTEPConfig into per-node CiliumVTEPNodeConfig",

	cell.Invoke(registerVTEPResourceManager),
)
