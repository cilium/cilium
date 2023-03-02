// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"fmt"
	"strconv"

	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/u8proto"
)

type ctMapAuthenticator struct {
	endpointManager endpointmanager.EndpointsLookup
}

func newCtMapAuthenticator(endpointManager endpointmanager.EndpointsLookup) datapathAuthenticator {
	return &ctMapAuthenticator{
		endpointManager: endpointManager,
	}
}

func (r *ctMapAuthenticator) markAuthenticated(dn *monitor.DropNotify, ci *monitor.ConnectionInfo, _ *authResult) error {
	ep := r.endpointManager.LookupCiliumID(dn.Source)
	if ep == nil {
		// Maybe endpoint was deleted?
		log.WithField(logfields.EndpointID, dn.Source).Debug("auth: Cannot find Endpoint")
		return nil
	}

	srcAddr := ci.SrcIP.String() + ":" + strconv.FormatUint(uint64(ci.SrcPort), 10)
	dstAddr := ci.DstIP.String() + ":" + strconv.FormatUint(uint64(ci.DstPort), 10)

	proto, err := u8proto.ParseProtocol(ci.Proto)
	if err != nil {
		return fmt.Errorf("cannot parse protocol: %w", err)
	}

	/* Update CT flags as authorized. */
	if err := ctmap.Update(ep.ConntrackName(), srcAddr, dstAddr, proto, isIngress(dn),
		func(entry *ctmap.CtEntry) error {
			before := entry.Flags
			if entry.Flags&ctmap.AuthRequired != 0 {
				entry.Flags = entry.Flags &^ ctmap.AuthRequired
				log.Debugf("auth: Cleared auth flag for %v->%v (%v), before %v after %v",
					srcAddr, dstAddr, proto, before&ctmap.AuthRequired, entry.Flags&ctmap.AuthRequired)
			}
			return nil
		}); err != nil {
		return fmt.Errorf("conntrack map update failed: %w", err)
	}

	return nil
}
