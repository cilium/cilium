// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"github.com/cilium/hive/cell"
)

// Cell implements the CID Controller. It subscribes to CID, CES, Pods
// and Namespace events and reconciles the state of CID in the cluster.
var Cell = cell.Module(
	"k8s-cid-controller",
	"Cilium Identity Controller Operator",
	cell.Invoke(registerController),
)

// SharedConfig contains the configuration that is shared between
// this module and others.
// It is a temporary solution meant to avoid polluting this module with a direct
// dependency on global operator and daemon configurations.
type SharedConfig struct {
	// EnableOperatorManageCIDs enables operator to manage Cilium Identities by
	// running a Cilium Identity controller.
	EnableOperatorManageCIDs bool

	// EnableCiliumEndpointSlice indicates if the Cilium Endpoint Slice feature is
	// enabled.
	EnableCiliumEndpointSlice bool
}
