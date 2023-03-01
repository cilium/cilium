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
	"github.com/cilium/cilium/pkg/ip"
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
	authType := getAuthType(dn)
	policyType := getPolicyType(dn)

	log.Debugf("auth: %s Policy is requiring authentication type %s for identity %d->%d, endpoint %s->%s",
		policyType, authType, dn.SrcLabel, dn.DstLabel, ci.SrcIP, ci.DstIP)

	// Authenticate according to the requested auth type
	h, ok := a.authHandlers[authType]
	if !ok {
		log.WithField(logfields.AuthType, authType.String()).Warning("auth: Unknown requested auth type")
		return
	}

	authReq, err := a.buildAuthRequest(dn, ci)
	if err != nil {
		log.WithError(err).Warning("auth: Failed to gather auth request information")
		return
	}

	authResp, err := h.authenticate(authReq)
	if err != nil {
		log.WithError(err).WithField(logfields.AuthType, authType.String()).Warning("auth: Failed to authenticate")
		return
	}

	if err := a.markConnectionAsAuthenticated(dn, ci, authResp); err != nil {
		log.WithError(err).WithField(logfields.Protocol, ci.Proto).Warning("auth: failed to write auth map")
		return
	}

	log.Debugf("auth: Successfully authenticated request for identity %s->%s, endpoint %s->%s, host %s->%s",
		dn.SrcLabel, dn.DstLabel, ci.SrcIP, ci.DstIP, authReq.srcHostIP, authReq.dstHostIP)
}

func (a *authManager) buildAuthRequest(dn *monitor.DropNotify, ci *monitor.ConnectionInfo) (*authRequest, error) {
	srcHostIP := a.hostIPForConnIP(ci.SrcIP)
	if srcHostIP == nil {
		return nil, fmt.Errorf("failed to get host IP of connection source IP %s", ci.SrcIP)
	}

	dstHostIP := a.hostIPForConnIP(ci.DstIP)
	if dstHostIP == nil {
		return nil, fmt.Errorf("failed to get host IP of connection destination IP %s", ci.DstIP)

	}

	return &authRequest{
		srcIdentity: dn.SrcLabel,
		dstIdentity: dn.DstLabel,
		srcHostIP:   srcHostIP,
		dstHostIP:   dstHostIP,
	}, nil
}

func (a *authManager) hostIPForConnIP(connIP net.IP) net.IP {
	hostIP := a.ipCache.GetHostIP(connIP.String())
	if hostIP != nil {
		return hostIP
	}

	// Checking for Cilium's internal IP (cilium_host).
	// This might be the case when checking ingress auth after egress L7 policies are applied and therefore traffic
	// gets rerouted via Cilium's envoy proxy.
	if ip.IsIPv4(connIP) {
		return a.ipCache.GetHostIP(fmt.Sprintf("%s/32", connIP))
	} else if ip.IsIPv6(connIP) {
		return a.ipCache.GetHostIP(fmt.Sprintf("%s/128", connIP))
	}

	return nil
}

func (a *authManager) markConnectionAsAuthenticated(dn *monitor.DropNotify, ci *monitor.ConnectionInfo, resp *authResponse) error {
	ep := a.endpointManager.LookupCiliumID(dn.Source)
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
				log.Debugf("auth: Cleared auth flag, before %v after %v",
					before&ctmap.AuthRequired, entry.Flags&ctmap.AuthRequired)
			}
			return nil
		}); err != nil {
		return fmt.Errorf("conntrack map update failed: %w", err)
	}

	return nil
}

func isIngress(dn *monitor.DropNotify) bool {
	// DropNotify.DstID is 0 for egress, non-zero for Ingress
	return dn.DstID != 0
}

func getAuthType(dn *monitor.DropNotify) policy.AuthType {
	// Requested authentication type is in DropNotify.ExtError field
	return policy.AuthType(dn.ExtError)
}

func getPolicyType(dn *monitor.DropNotify) string {
	if isIngress(dn) {
		return "Ingress"
	}
	return "Egress"
}
