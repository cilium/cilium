// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policycell

import (
	"github.com/cilium/hive/cell"

	identityCache "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	policyDirectory "github.com/cilium/cilium/pkg/policy/directory"
	policyK8s "github.com/cilium/cilium/pkg/policy/k8s"
	policyRepo "github.com/cilium/cilium/pkg/policy/repository"
)

// Cell is a parent cell for security policy and identity management.
var Cell = cell.Module(
	"policy",
	"Contains cells that make up security policy and identity management",

	// Provides the PolicyRepository and PolicyUpdater.
	policyRepo.Cell,

	// K8s policy resource watcher cell. It depends on the half-initialized daemon which is
	// resolved by newDaemonPromise()
	policyK8s.Cell,

	// Directory policy watcher cell.
	policyDirectory.Cell,

	// Provides IdentityAllocators (Responsible for allocating security identities)
	identityCache.Cell,

	// IdentityManager maintains the set of identities and a count of its
	// users.
	identitymanager.Cell,
)
