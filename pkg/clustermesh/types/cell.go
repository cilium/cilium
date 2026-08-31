// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/hive/cell"
)

var (
	// ClusterInfoCell provides and validates the configured information about the local cluster.
	ClusterInfoCell = cell.Group(
		cell.Config(DefaultClusterInfo),
		cell.Invoke(ClusterInfo.InitClusterIDMax),
		cell.Invoke(ClusterInfo.Validate),
	)

	// PolicyConfigCell provides information about the ClusterMesh and policies.
	PolicyConfigCell = cell.Config(DefaultPolicyConfig)
)
