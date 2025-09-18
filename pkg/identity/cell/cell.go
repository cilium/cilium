// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identityapi

import (
	"github.com/cilium/hive/cell"

	identityapi "github.com/cilium/cilium/pkg/identity/api"
	identitycache "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/identity/restoration"
)

// Cell provides the identity controlplane that is responsible to allocate and manage security identities
var Cell = cell.Module(
	"identity",
	"Identity ControlPlane",

	// IdentityManager maintains the set of identities and a count of its users.
	identitymanager.Cell,

	// Provides IdentityAllocators (Responsible for allocating security identities)
	identitycache.Cell,

	// IdentityApiHandler provides the Identity Cilium API
	identityapi.Cell,

	// LocalIdentityRestorer restores the identities at startup
	restoration.Cell,
)
