// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identityapi

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	policyapi "github.com/cilium/cilium/api/v1/server/restapi/policy"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
)

// Cell provides the identity API handlers
var Cell = cell.Module(
	"identity-api",
	"Identity API handlers",

	cell.Provide(newIdentityApiHandler),
)

type identityApiHandlerParams struct {
	cell.In

	Logger            *slog.Logger
	IdentityAllocator identitycell.CachingIdentityAllocator
	IdentityManager   identitymanager.IDManager
}

type identityApiHandlerOut struct {
	cell.Out

	GetIdentityHandler          policyapi.GetIdentityHandler
	GetIdentityIDHandler        policyapi.GetIdentityIDHandler
	GetIdentityEndpointsHandler policyapi.GetIdentityEndpointsHandler
}
