// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/u8proto"
)

type authManager struct {
	endpointManager endpointmanager.EndpointsLookup
	authHandlers    map[policy.AuthType]authHandler
	ipCache         ipCache
}

// ipCache is the set of interactions the auth manager performs with the IPCache
type ipCache interface {
	GetHostIP(ip string) net.IP
}

// authHandler is responsible to handle authentication for a specific auth type
type authHandler interface {
	authenticate(*authRequest) (*authResponse, error)
	authType() policy.AuthType
}

type authRequest struct {
	srcIdentity identity.NumericIdentity
	dstIdentity identity.NumericIdentity
	srcHostIP   net.IP
	dstHostIP   net.IP
}

type authResponse struct {
	expiryTime time.Time
}

func newAuthManager(epMgr endpointmanager.EndpointsLookup, authHandlers []authHandler) (*authManager, error) {
	ahs := map[policy.AuthType]authHandler{}
	for _, ah := range authHandlers {
		if _, ok := ahs[ah.authType()]; ok {
			return nil, fmt.Errorf("multiple handlers for auth type: %s", ah.authType())
		}
		ahs[ah.authType()] = ah
	}

	return &authManager{
		endpointManager: epMgr,
		authHandlers:    ahs,
	}, nil
}

func (a *authManager) AuthRequired(dn *monitor.DropNotify, ci *monitor.ConnectionInfo) {
	// Requested authentication type is in DropNotify.ExtError field
	authType := policy.AuthType(dn.ExtError)

	// DropNotify.DstID is 0 for egress, non-zero for Ingress
	ingress := dn.DstID != 0

	srcAddr := ci.SrcIP.String() + ":" + strconv.FormatUint(uint64(ci.SrcPort), 10)
	dstAddr := ci.DstIP.String() + ":" + strconv.FormatUint(uint64(ci.DstPort), 10)

	log.Debugf("auth: Policy is requiring authentication type %s for identity %d->%d, %s %s->%s, ingress: %t",
		authType.String(), dn.SrcLabel, dn.DstLabel, ci.Proto, srcAddr, dstAddr, ingress)

	proto, err := u8proto.ParseProtocol(ci.Proto)
	if err != nil {
		log.WithError(err).WithField(logfields.Protocol, ci.Proto).Warning("auth: Cannot parse protocol")
		return
	}

	ep := a.endpointManager.LookupCiliumID(dn.Source)
	if ep == nil {
		// Maybe endpoint was deleted?
		log.WithField(logfields.EndpointID, dn.Source).Debug("auth: Cannot find Endpoint")
		return
	}

	// Authenticate according to the requested auth type
	h, ok := a.authHandlers[authType]
	if !ok {
		log.WithField(logfields.AuthType, authType.String()).Warning("auth: Unknown requested auth type")
		return
	}

	if _, err := h.authenticate(&authRequest{}); err != nil {
		log.WithError(err).WithField(logfields.AuthType, authType.String()).Warning("auth: Failed to authenticate")
		return
	}

	/* Update CT flags as authorized. */
	if err := ctmap.Update(ep.ConntrackName(), srcAddr, dstAddr, proto, ingress,
		func(entry *ctmap.CtEntry) error {
			before := entry.Flags
			if entry.Flags&ctmap.AuthRequired != 0 {
				entry.Flags = entry.Flags &^ ctmap.AuthRequired
				log.Debugf("auth: Cleared auth flag, before %v after %v",
					before&ctmap.AuthRequired, entry.Flags&ctmap.AuthRequired)
			}
			return nil
		}); err != nil {
		log.WithError(err).Warning("auth: Conntrack map update failed")
	}
}
