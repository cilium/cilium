// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reflector

import "github.com/cilium/cilium/pkg/hive"

// Reflector reflects external data into a statedb table
type Reflector[Obj any] interface {
	hive.HookInterface // Can be started and stopped.
}
