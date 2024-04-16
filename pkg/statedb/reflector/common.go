// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflector

import (
	"github.com/cilium/hive/cell"
)

// Reflector reflects external data into a statedb table
type Reflector[Obj any] interface {
	cell.HookInterface // Can be started and stopped.
}
