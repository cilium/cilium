// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lifecycle

import "context"

// HookContext is a context passed to a lifecycle hook that is cancelled
// in case of timeout. Hooks that perform long blocking operations directly
// in the start or stop function (e.g. connecting to external services to
// initialize) must abort any such operation if this context is cancelled.
type HookContext context.Context

// HookInterface mirrors the Hook interface from pkg/hive/lifecycle.go.
// Because pkg/hive/cell depends on HookInterface then we need to have a
// copy of it here.
// Hive provides a "cell" version of this HookInterface interface that does
// not depend on pkg/hive/lifecycle.go thus allowing the cell package to define
// lifecycle hooks.
type HookInterface interface {
	Start(HookContext) error
	Stop(HookContext) error
}

// Lifecycle enables cells to register start and stop hooks, either
// from a constructor or an invoke function.
type Lifecycle interface {
	Append(HookInterface)
}
