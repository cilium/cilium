// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"strconv"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/u8proto"
)

type AuthManager struct {
	endpointManager endpointmanager.EndpointsLookup
}

func NewAuthManager(epMgr endpointmanager.EndpointsLookup) *AuthManager {
	return &AuthManager{
		endpointManager: epMgr,
	}
}

func (a *AuthManager) AuthRequired(dn *monitor.DropNotify, ci *monitor.ConnectionInfo) {
	// Requested authentication type is in DropNotify.ExtError field
	authType := policy.AuthType(dn.ExtError)

	// DropNotify.DstID is 0 for egress, non-zero for Ingress
	ingress := dn.DstID != 0

	srcAddr := ci.SrcIP.String() + ":" + strconv.FormatUint(uint64(ci.SrcPort), 10)
	dstAddr := ci.DstIP.String() + ":" + strconv.FormatUint(uint64(ci.DstPort), 10)

	log.Debugf("policy: Authentication type %s required for identity %d->%d, %s %s->%s",
		authType.String(), dn.SrcLabel, dn.DstLabel, ci.Proto, srcAddr, dstAddr)

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
	switch authType {
	case policy.AuthTypeNull:
		// Authentication trivially done
	default:
		log.WithField(logfields.AuthType, authType.String()).Warning("auth: Unknown requested auth type")
		return
	}

	/* Update CT flags as authorized. */
	err = ctmap.Update(ep.ConntrackName(), srcAddr, dstAddr, proto, ingress,
		func(entry *ctmap.CtEntry) error {
			before := entry.Flags
			if entry.Flags&ctmap.AuthRequired != 0 {
				entry.Flags = entry.Flags &^ ctmap.AuthRequired
				log.Debugf("auth: Cleared auth flag, before %v after %v",
					before&ctmap.AuthRequired, entry.Flags&ctmap.AuthRequired)
			}
			return nil
		})
	if err != nil {
		log.WithError(err).Warning("auth: Conntrack map update failed")
	}
}
