// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identityapi

import (
	"log/slog"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	policyapi "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/identity"
	identitycell "github.com/cilium/cilium/pkg/identity/cache/cell"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func newIdentityApiHandler(params identityApiHandlerParams) identityApiHandlerOut {
	return identityApiHandlerOut{
		GetIdentityHandler: &getIdentityHandler{
			logger:            params.Logger,
			identityAllocator: params.IdentityAllocator,
		},
		GetIdentityIDHandler: &getIdentityIDHandler{
			logger:            params.Logger,
			identityAllocator: params.IdentityAllocator,
		},
		GetIdentityEndpointsHandler: &getIdentityEndpointsHandler{
			logger:          params.Logger,
			identityManager: params.IdentityManager,
		},
	}
}

type getIdentityHandler struct {
	logger            *slog.Logger
	identityAllocator identitycell.CachingIdentityAllocator
}

func (h *getIdentityHandler) Handle(params policyapi.GetIdentityParams) middleware.Responder {
	h.logger.Debug("GET /identity request", logfields.Params, logfields.Repr(params))

	identities := []*models.Identity{}
	if params.Labels == nil {
		// if labels is nil, return all identities from the kvstore
		// This is in response to "identity list" command
		identities = h.identityAllocator.GetIdentities()
	} else {
		identity := h.identityAllocator.LookupIdentity(params.HTTPRequest.Context(), labels.NewLabelsFromModel(params.Labels))
		if identity == nil {
			return policyapi.NewGetIdentityIDNotFound()
		}

		identities = append(identities, identitymodel.CreateModel(identity))
	}

	return policyapi.NewGetIdentityOK().WithPayload(identities)
}

type getIdentityIDHandler struct {
	logger            *slog.Logger
	identityAllocator identitycell.CachingIdentityAllocator
}

func (h *getIdentityIDHandler) Handle(params policyapi.GetIdentityIDParams) middleware.Responder {
	h.logger.Debug("GET /identity/<ID> request", logfields.Params, logfields.Repr(params))

	nid, err := identity.ParseNumericIdentity(params.ID)
	if err != nil {
		return policyapi.NewGetIdentityIDBadRequest()
	}

	identity := h.identityAllocator.LookupIdentityByID(params.HTTPRequest.Context(), nid)
	if identity == nil {
		return policyapi.NewGetIdentityIDNotFound()
	}

	return policyapi.NewGetIdentityIDOK().WithPayload(identitymodel.CreateModel(identity))
}

type getIdentityEndpointsHandler struct {
	logger          *slog.Logger
	identityManager identitymanager.IDManager
}

func (h *getIdentityEndpointsHandler) Handle(params policyapi.GetIdentityEndpointsParams) middleware.Responder {
	h.logger.Debug("GET /identity/endpoints request", logfields.Params, logfields.Repr(params))

	identities := h.identityManager.GetIdentityModels()

	return policyapi.NewGetIdentityEndpointsOK().WithPayload(identities)
}
