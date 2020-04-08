// Copyright 2016-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/go-openapi/runtime/middleware"
)

type getIdentity struct {
	d *Daemon
}

func newGetIdentityHandler(d *Daemon) GetIdentityHandler { return &getIdentity{d: d} }

func (h *getIdentity) Handle(params GetIdentityParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /identity request")

	identities := []*models.Identity{}
	if params.Labels == nil {
		// if labels is nil, return all identities from the kvstore
		// This is in response to "identity list" command
		identities = h.d.identityAllocator.GetIdentities()
	} else {
		identity := h.d.identityAllocator.LookupIdentity(params.HTTPRequest.Context(), labels.NewLabelsFromModel(params.Labels))
		if identity == nil {
			return NewGetIdentityIDNotFound()
		}

		identities = append(identities, identitymodel.CreateModel(identity))
	}

	return NewGetIdentityOK().WithPayload(identities)
}

type getIdentityID struct {
	c *cache.CachingIdentityAllocator
}

func newGetIdentityIDHandler(c *cache.CachingIdentityAllocator) GetIdentityIDHandler {
	return &getIdentityID{c: c}
}

func (h *getIdentityID) Handle(params GetIdentityIDParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /identity/<ID> request")

	nid, err := identity.ParseNumericIdentity(params.ID)
	if err != nil {
		return NewGetIdentityIDBadRequest()
	}

	identity := h.c.LookupIdentityByID(params.HTTPRequest.Context(), nid)
	if identity == nil {
		return NewGetIdentityIDNotFound()
	}

	return NewGetIdentityIDOK().WithPayload(identitymodel.CreateModel(identity))
}

type getIdentityEndpoints struct{}

func newGetIdentityEndpointsIDHandler(d *Daemon) GetIdentityEndpointsHandler {
	return &getIdentityEndpoints{}
}

func (h *getIdentityEndpoints) Handle(params GetIdentityEndpointsParams) middleware.Responder {
	log.WithField(logfields.Params, logfields.Repr(params)).Debug("GET /identity/endpoints request")

	identities := identitymanager.GetIdentityModels()

	return NewGetIdentityEndpointsOK().WithPayload(identities)
}
