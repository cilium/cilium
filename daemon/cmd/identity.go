// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"net"
	"net/netip"

	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	identitymodel "github.com/cilium/cilium/pkg/identity/model"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/k8s/client/clientset/versioned"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
	c cache.IdentityAllocator
}

func newGetIdentityIDHandler(c cache.IdentityAllocator) GetIdentityIDHandler {
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

// CachingIdentityAllocator provides an abstraction over the concrete type in
// pkg/identity/cache so that the underlying implementation can be mocked out
// in unit tests.
type CachingIdentityAllocator interface {
	cache.IdentityAllocator
	clustermesh.RemoteIdentityWatcher

	InitIdentityAllocator(versioned.Interface) <-chan struct{}
	Close()
}

type cachingIdentityAllocator struct {
	*cache.CachingIdentityAllocator
	ipcache *ipcache.IPCache
}

func (c cachingIdentityAllocator) AllocateCIDRsForIPs(ips []net.IP, newlyAllocatedIdentities map[netip.Prefix]*identity.Identity) ([]*identity.Identity, error) {
	return c.ipcache.AllocateCIDRsForIPs(ips, newlyAllocatedIdentities)
}

func (c cachingIdentityAllocator) ReleaseCIDRIdentitiesByID(ctx context.Context, identities []identity.NumericIdentity) {
	c.ipcache.ReleaseCIDRIdentitiesByID(ctx, identities)
}
