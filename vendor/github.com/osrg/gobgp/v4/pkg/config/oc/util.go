// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oc

import (
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"time"

	tspb "google.golang.org/protobuf/types/known/timestamppb"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

// Returns config file type by retrieving extension from the given path.
// If no corresponding type found, returns the given def as the default value.
func detectConfigFileType(path, def string) string {
	switch ext := filepath.Ext(path); ext {
	case ".toml":
		return "toml"
	case ".yaml", ".yml":
		return "yaml"
	case ".json":
		return "json"
	default:
		return def
	}
}

// yaml is decoded as []interface{}
// but toml is decoded as []map[string]interface{}.
// currently, viper can't hide this difference.
// handle the difference here.
func extractArray(intf any) ([]any, error) {
	if intf != nil {
		list, ok := intf.([]any)
		if ok {
			return list, nil
		}
		l, ok := intf.([]map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid configuration: neither []interface{} nor []map[string]interface{}")
		}
		list = make([]any, 0, len(l))
		for _, m := range l {
			list = append(list, m)
		}
		return list, nil
	}
	return nil, nil
}

func getIPv6LinkLocalAddress(ifname string) (string, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return "", err
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		ip := addr.(*net.IPNet).IP
		if ip.To4() == nil && ip.IsLinkLocalUnicast() {
			return fmt.Sprintf("%s%%%s", ip.String(), ifname), nil
		}
	}
	return "", fmt.Errorf("no ipv6 link local address for %s", ifname)
}

func (b *BgpConfigSet) getPeerGroup(n string) (*PeerGroup, error) {
	if n == "" {
		return nil, nil
	}
	for _, pg := range b.PeerGroups {
		if n == pg.Config.PeerGroupName {
			return &pg, nil
		}
	}
	return nil, fmt.Errorf("no such peer-group: %s", n)
}

func (d *DynamicNeighbor) validate(b *BgpConfigSet) error {
	if d.Config.PeerGroup == "" {
		return fmt.Errorf("dynamic neighbor requires the peer group config")
	}

	if _, err := b.getPeerGroup(d.Config.PeerGroup); err != nil {
		return err
	}
	if _, _, err := net.ParseCIDR(d.Config.Prefix.String()); err != nil {
		return fmt.Errorf("invalid dynamic neighbor prefix %s", d.Config.Prefix)
	}
	return nil
}

func (n *Neighbor) IsConfederationMember(g *Global) bool {
	return slices.Contains(g.Confederation.Config.MemberAsList, n.Config.PeerAs)
}

func (n *Neighbor) IsConfederation(g *Global) bool {
	if n.Config.PeerAs == g.Config.As {
		return true
	}
	return n.IsConfederationMember(g)
}

func (n *Neighbor) IsEBGPPeer(g *Global) bool {
	return n.Config.PeerAs != n.Config.LocalAs
}

func (n *Neighbor) CreateRfMap() map[bgp.Family]bgp.BGPAddPathMode {
	rfMap := make(map[bgp.Family]bgp.BGPAddPathMode)
	for _, af := range n.AfiSafis {
		mode := bgp.BGP_ADD_PATH_NONE
		if af.AddPaths.State.Receive {
			mode |= bgp.BGP_ADD_PATH_RECEIVE
		}
		if af.AddPaths.State.SendMax > 0 {
			mode |= bgp.BGP_ADD_PATH_SEND
		}
		rfMap[af.State.Family] = mode
	}
	return rfMap
}

func (n *Neighbor) GetAfiSafi(family bgp.Family) *AfiSafi {
	for _, a := range n.AfiSafis {
		if string(a.Config.AfiSafiName) == family.String() {
			return &a
		}
	}
	return nil
}

func (n *Neighbor) ExtractNeighborAddress() (string, error) {
	addr := n.State.NeighborAddress
	if !addr.IsValid() {
		addr = n.Config.NeighborAddress
		if !addr.IsValid() {
			return "", fmt.Errorf("NeighborAddress is not configured")
		}
	}
	return addr.String(), nil
}

func (n *Neighbor) IsAddPathReceiveEnabled(family bgp.Family) bool {
	for _, af := range n.AfiSafis {
		if af.State.Family == family {
			return af.AddPaths.State.Receive
		}
	}
	return false
}

type AfiSafis []AfiSafi

func (c AfiSafis) ToRfList() ([]bgp.Family, error) {
	rfs := make([]bgp.Family, 0, len(c))
	for _, af := range c {
		rfs = append(rfs, af.State.Family)
	}
	return rfs, nil
}

func inSlice(n Neighbor, b []Neighbor) int {
	for i, nb := range b {
		if nb.State.NeighborAddress == n.State.NeighborAddress {
			return i
		}
	}
	return -1
}

func existPeerGroup(n string, b []PeerGroup) int {
	for i, nb := range b {
		if nb.Config.PeerGroupName == n {
			return i
		}
	}
	return -1
}

func isAfiSafiChanged(x, y []AfiSafi) bool {
	if len(x) != len(y) {
		return true
	}
	m := make(map[string]AfiSafi)
	for i, e := range x {
		m[string(e.Config.AfiSafiName)] = x[i]
	}
	for _, e := range y {
		if v, ok := m[string(e.Config.AfiSafiName)]; !ok || !v.Config.Equal(&e.Config) || !v.AddPaths.Config.Equal(&e.AddPaths.Config) || !v.MpGracefulRestart.Config.Equal(&e.MpGracefulRestart.Config) {
			return true
		}
	}
	return false
}

func (n *Neighbor) NeedsResendOpenMessage(new *Neighbor) bool {
	return !n.Config.Equal(&new.Config) ||
		!n.Transport.Config.Equal(&new.Transport.Config) ||
		!n.AddPaths.Config.Equal(&new.AddPaths.Config) ||
		!n.AsPathOptions.Config.Equal(&new.AsPathOptions.Config) ||
		!n.GracefulRestart.Config.Equal(&new.GracefulRestart.Config) ||
		isAfiSafiChanged(n.AfiSafis, new.AfiSafis) ||
		!n.EbgpMultihop.Config.Equal(&new.EbgpMultihop.Config) ||
		!n.TtlSecurity.Config.Equal(&new.TtlSecurity.Config)
}

// TODO: these regexp are duplicated in api
var _regexpPrefixMaskLengthRange = regexp.MustCompile(`(\d+)\.\.(\d+)`)

func ParseMaskLength(prefix, mask string) (int, int, error) {
	_, ipNet, err := net.ParseCIDR(prefix)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid prefix: %s", prefix)
	}
	if mask == "" {
		l, _ := ipNet.Mask.Size()
		return l, l, nil
	}
	elems := _regexpPrefixMaskLengthRange.FindStringSubmatch(mask)
	if len(elems) != 3 {
		return 0, 0, fmt.Errorf("invalid mask length range: %s", mask)
	}
	// we've already checked the range is sane by regexp
	min, _ := strconv.ParseUint(elems[1], 10, 8)
	max, _ := strconv.ParseUint(elems[2], 10, 8)
	if min > max {
		return 0, 0, fmt.Errorf("invalid mask length range: %s", mask)
	}
	if ipv4 := ipNet.IP.To4(); ipv4 != nil {
		f := func(i uint64) bool {
			return i <= 32
		}
		if !f(min) || !f(max) {
			return 0, 0, fmt.Errorf("ipv4 mask length range outside scope :%s", mask)
		}
	} else {
		f := func(i uint64) bool {
			return i <= 128
		}
		if !f(min) || !f(max) {
			return 0, 0, fmt.Errorf("ipv6 mask length range outside scope :%s", mask)
		}
	}
	return int(min), int(max), nil
}

func extractFamilyFromConfigAfiSafi(c *AfiSafi) uint32 {
	if c == nil {
		return 0
	}
	// If address family value is already stored in AfiSafiState structure,
	// we prefer to use this value.
	if c.State.Family != 0 {
		return uint32(c.State.Family)
	}
	// In case that Neighbor structure came from CLI or gRPC, address family
	// value in AfiSafiState structure can be omitted.
	// Here extracts value from AfiSafiName field in AfiSafiConfig structure.
	if rf, err := bgp.GetFamily(string(c.Config.AfiSafiName)); err == nil {
		return uint32(rf)
	}
	// Ignores invalid address family name
	return 0
}

func newAfiSafiConfigFromConfigStruct(c *AfiSafi) *api.AfiSafiConfig {
	rf := extractFamilyFromConfigAfiSafi(c)
	family := bgp.Family(rf)
	return &api.AfiSafiConfig{
		Family:  &api.Family{Afi: api.Family_Afi(family.Afi()), Safi: api.Family_Safi(family.Safi())},
		Enabled: c.Config.Enabled,
	}
}

func newApplyPolicyFromConfigStruct(c *ApplyPolicy) *api.ApplyPolicy {
	f := func(t DefaultPolicyType) api.RouteAction {
		switch t {
		case DEFAULT_POLICY_TYPE_ACCEPT_ROUTE:
			return api.RouteAction_ROUTE_ACTION_ACCEPT
		case DEFAULT_POLICY_TYPE_REJECT_ROUTE:
			return api.RouteAction_ROUTE_ACTION_REJECT
		}
		return api.RouteAction_ROUTE_ACTION_UNSPECIFIED
	}
	applyPolicy := &api.ApplyPolicy{
		ImportPolicy: &api.PolicyAssignment{
			Direction:     api.PolicyDirection_POLICY_DIRECTION_IMPORT,
			DefaultAction: f(c.Config.DefaultImportPolicy),
		},
		ExportPolicy: &api.PolicyAssignment{
			Direction:     api.PolicyDirection_POLICY_DIRECTION_EXPORT,
			DefaultAction: f(c.Config.DefaultExportPolicy),
		},
	}

	for _, pname := range c.Config.ImportPolicyList {
		applyPolicy.ImportPolicy.Policies = append(applyPolicy.ImportPolicy.Policies, &api.Policy{Name: pname})
	}
	for _, pname := range c.Config.ExportPolicyList {
		applyPolicy.ExportPolicy.Policies = append(applyPolicy.ExportPolicy.Policies, &api.Policy{Name: pname})
	}

	return applyPolicy
}

func newPrefixLimitFromConfigStruct(c *AfiSafi) *api.PrefixLimit {
	if c.PrefixLimit.Config.MaxPrefixes == 0 {
		return nil
	}
	return &api.PrefixLimit{
		Family:               &api.Family{Afi: api.Family_Afi(c.State.Family.Afi()), Safi: api.Family_Safi(c.State.Family.Safi())},
		MaxPrefixes:          c.PrefixLimit.Config.MaxPrefixes,
		ShutdownThresholdPct: uint32(c.PrefixLimit.Config.ShutdownThresholdPct),
	}
}

func newRouteTargetMembershipFromConfigStruct(c *RouteTargetMembership) *api.RouteTargetMembership {
	return &api.RouteTargetMembership{
		Config: &api.RouteTargetMembershipConfig{
			DeferralTime: uint32(c.Config.DeferralTime),
		},
	}
}

func newLongLivedGracefulRestartFromConfigStruct(c *LongLivedGracefulRestart) *api.LongLivedGracefulRestart {
	return &api.LongLivedGracefulRestart{
		Config: &api.LongLivedGracefulRestartConfig{
			Enabled:     c.Config.Enabled,
			RestartTime: c.Config.RestartTime,
		},
		State: &api.LongLivedGracefulRestartState{
			Enabled:                 c.State.Enabled,
			Received:                c.State.Received,
			Advertised:              c.State.Advertised,
			PeerRestartTime:         c.State.PeerRestartTime,
			PeerRestartTimerExpired: c.State.PeerRestartTimerExpired,
			Running:                 c.State.Running,
		},
	}
}

func newAddPathsFromConfigStruct(c *AddPaths) *api.AddPaths {
	return &api.AddPaths{
		Config: &api.AddPathsConfig{
			Receive: c.Config.Receive,
			SendMax: uint32(c.Config.SendMax),
		},
	}
}

func newRouteSelectionOptionsFromConfigStruct(c *RouteSelectionOptions) *api.RouteSelectionOptions {
	return &api.RouteSelectionOptions{
		Config: &api.RouteSelectionOptionsConfig{
			AlwaysCompareMed:        c.Config.AlwaysCompareMed,
			IgnoreAsPathLength:      c.Config.IgnoreAsPathLength,
			ExternalCompareRouterId: c.Config.ExternalCompareRouterId,
			AdvertiseInactiveRoutes: c.Config.AdvertiseInactiveRoutes,
			EnableAigp:              c.Config.EnableAigp,
			IgnoreNextHopIgpMetric:  c.Config.IgnoreNextHopIgpMetric,
		},
	}
}

func newMpGracefulRestartFromConfigStruct(c *MpGracefulRestart) *api.MpGracefulRestart {
	return &api.MpGracefulRestart{
		Config: &api.MpGracefulRestartConfig{
			Enabled: c.Config.Enabled,
		},
		State: &api.MpGracefulRestartState{
			Enabled:          c.State.Enabled,
			Received:         c.State.Received,
			Advertised:       c.State.Advertised,
			EndOfRibReceived: c.State.EndOfRibReceived,
			EndOfRibSent:     c.State.EndOfRibSent,
			Running:          c.State.Running,
		},
	}
}

func newUseMultiplePathsFromConfigStruct(c *UseMultiplePaths) *api.UseMultiplePaths {
	return &api.UseMultiplePaths{
		Config: &api.UseMultiplePathsConfig{
			Enabled: c.Config.Enabled,
		},
		Ebgp: &api.Ebgp{
			Config: &api.EbgpConfig{
				AllowMultipleAsn: c.Ebgp.Config.AllowMultipleAs,
				MaximumPaths:     c.Ebgp.Config.MaximumPaths,
			},
		},
		Ibgp: &api.Ibgp{
			Config: &api.IbgpConfig{
				MaximumPaths: c.Ibgp.Config.MaximumPaths,
			},
		},
	}
}

func newAfiSafiFromConfigStruct(c *AfiSafi) *api.AfiSafi {
	return &api.AfiSafi{
		MpGracefulRestart:        newMpGracefulRestartFromConfigStruct(&c.MpGracefulRestart),
		Config:                   newAfiSafiConfigFromConfigStruct(c),
		ApplyPolicy:              newApplyPolicyFromConfigStruct(&c.ApplyPolicy),
		RouteSelectionOptions:    newRouteSelectionOptionsFromConfigStruct(&c.RouteSelectionOptions),
		UseMultiplePaths:         newUseMultiplePathsFromConfigStruct(&c.UseMultiplePaths),
		PrefixLimits:             newPrefixLimitFromConfigStruct(c),
		RouteTargetMembership:    newRouteTargetMembershipFromConfigStruct(&c.RouteTargetMembership),
		LongLivedGracefulRestart: newLongLivedGracefulRestartFromConfigStruct(&c.LongLivedGracefulRestart),
		AddPaths:                 newAddPathsFromConfigStruct(&c.AddPaths),
	}
}

func ProtoTimestamp(secs int64) *tspb.Timestamp {
	if secs == 0 {
		return nil
	}
	return tspb.New(time.Unix(secs, 0))
}

func toPeerType(t PeerType) api.PeerType {
	switch t {
	case PEER_TYPE_EXTERNAL:
		return api.PeerType_PEER_TYPE_EXTERNAL
	default:
		return api.PeerType_PEER_TYPE_INTERNAL
	}
}

// bfdSessionStateToAPI maps oc BfdSessionState string values to api.BfdSessionState.
// Do not cast BfdSessionState.ToInt() to the API enum: YANG-derived indices (0..3) are
// one less than protobuf values (BFD_SESSION_STATE_UP=1, etc.).
func bfdSessionStateToAPI(s BfdSessionState) api.BfdSessionState {
	switch s {
	case BFD_SESSION_STATE_UP:
		return api.BfdSessionState_BFD_SESSION_STATE_UP
	case BFD_SESSION_STATE_DOWN:
		return api.BfdSessionState_BFD_SESSION_STATE_DOWN
	case BFD_SESSION_STATE_ADMIN_DOWN:
		return api.BfdSessionState_BFD_SESSION_STATE_ADMIN_DOWN
	case BFD_SESSION_STATE_INIT:
		return api.BfdSessionState_BFD_SESSION_STATE_INIT
	default:
		return api.BfdSessionState_BFD_SESSION_STATE_UNSPECIFIED
	}
}

func bfdDiagnosticCodeToAPI(d BfdDiagnosticCode) api.BfdDiagnosticCode {
	i := d.ToInt()
	if i < 0 || i > int(api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_REVERSE_CONCATENATED_PATH_DOWN) {
		return api.BfdDiagnosticCode_BFD_DIAGNOSTIC_CODE_NO_DIAGNOSTIC
	}
	return api.BfdDiagnosticCode(i)
}

func NewPeerFromConfigStruct(pconf *Neighbor) *api.Peer {
	afiSafis := make([]*api.AfiSafi, 0, len(pconf.AfiSafis))
	for _, f := range pconf.AfiSafis {
		if afiSafi := newAfiSafiFromConfigStruct(&f); afiSafi != nil {
			afiSafis = append(afiSafis, afiSafi)
		}
	}

	timer := pconf.Timers
	s := pconf.State
	localAddress := pconf.Transport.Config.LocalAddress
	if pconf.Transport.State.LocalAddress.IsValid() {
		localAddress = pconf.Transport.State.LocalAddress
	}
	remoteCap, err := apiutil.MarshalCapabilities(pconf.State.RemoteCapabilityList)
	if err != nil {
		return nil
	}
	localCap, err := apiutil.MarshalCapabilities(pconf.State.LocalCapabilityList)
	if err != nil {
		return nil
	}
	var removePrivate api.RemovePrivate
	switch pconf.Config.RemovePrivateAs {
	case REMOVE_PRIVATE_AS_OPTION_ALL:
		removePrivate = api.RemovePrivate_REMOVE_PRIVATE_ALL
	case REMOVE_PRIVATE_AS_OPTION_REPLACE:
		removePrivate = api.RemovePrivate_REMOVE_PRIVATE_REPLACE
	}
	var admin_state api.PeerState_AdminState
	switch s.AdminState {
	case ADMIN_STATE_UP:
		admin_state = api.PeerState_ADMIN_STATE_UP
	case ADMIN_STATE_DOWN:
		admin_state = api.PeerState_ADMIN_STATE_DOWN
	case ADMIN_STATE_PFX_CT:
		admin_state = api.PeerState_ADMIN_STATE_PFX_CT
	}
	var sessionState api.PeerState_SessionState
	switch s.SessionState {
	case SESSION_STATE_IDLE:
		sessionState = api.PeerState_SESSION_STATE_IDLE
	case SESSION_STATE_CONNECT:
		sessionState = api.PeerState_SESSION_STATE_CONNECT
	case SESSION_STATE_ACTIVE:
		sessionState = api.PeerState_SESSION_STATE_ACTIVE
	case SESSION_STATE_OPENSENT:
		sessionState = api.PeerState_SESSION_STATE_OPENSENT
	case SESSION_STATE_OPENCONFIRM:
		sessionState = api.PeerState_SESSION_STATE_OPENCONFIRM
	case SESSION_STATE_ESTABLISHED:
		sessionState = api.PeerState_SESSION_STATE_ESTABLISHED
	}

	return &api.Peer{
		ApplyPolicy: newApplyPolicyFromConfigStruct(&pconf.ApplyPolicy),
		Conf: &api.PeerConf{
			NeighborAddress:      pconf.Config.NeighborAddress.String(),
			PeerAsn:              pconf.Config.PeerAs,
			LocalAsn:             pconf.Config.LocalAs,
			Type:                 toPeerType(pconf.Config.PeerType),
			AuthPassword:         pconf.Config.AuthPassword,
			RouteFlapDamping:     pconf.Config.RouteFlapDamping,
			Description:          pconf.Config.Description,
			PeerGroup:            pconf.Config.PeerGroup,
			NeighborInterface:    pconf.Config.NeighborInterface,
			Vrf:                  pconf.Config.Vrf,
			AllowOwnAsn:          uint32(pconf.AsPathOptions.Config.AllowOwnAs),
			AllowAspathLoopLocal: pconf.AsPathOptions.Config.AllowAsPathLoopLocal,
			RemovePrivate:        removePrivate,
			ReplacePeerAsn:       pconf.AsPathOptions.Config.ReplacePeerAs,
			AdminDown:            pconf.Config.AdminDown,
			SendSoftwareVersion:  pconf.Config.SendSoftwareVersion,
		},
		State: &api.PeerState{
			SessionState: sessionState,
			AdminState:   admin_state,
			Messages: &api.Messages{
				Received: &api.Message{
					Notification:   pconf.State.Messages.Received.Notification,
					Update:         pconf.State.Messages.Received.Update,
					Open:           pconf.State.Messages.Received.Open,
					Keepalive:      pconf.State.Messages.Received.Keepalive,
					Refresh:        pconf.State.Messages.Received.Refresh,
					Discarded:      pconf.State.Messages.Received.Discarded,
					Total:          pconf.State.Messages.Received.Total,
					WithdrawUpdate: uint64(pconf.State.Messages.Received.WithdrawUpdate),
					WithdrawPrefix: uint64(pconf.State.Messages.Received.WithdrawPrefix),
				},
				Sent: &api.Message{
					Notification: pconf.State.Messages.Sent.Notification,
					Update:       pconf.State.Messages.Sent.Update,
					Open:         pconf.State.Messages.Sent.Open,
					Keepalive:    pconf.State.Messages.Sent.Keepalive,
					Refresh:      pconf.State.Messages.Sent.Refresh,
					Discarded:    pconf.State.Messages.Sent.Discarded,
					Total:        pconf.State.Messages.Sent.Total,
				},
			},
			PeerAsn:         s.PeerAs,
			LocalAsn:        s.LocalAs,
			Type:            toPeerType(s.PeerType),
			NeighborAddress: pconf.State.NeighborAddress.String(),
			Queues:          &api.Queues{},
			RemoteCap:       remoteCap,
			LocalCap:        localCap,
			RouterId:        s.RemoteRouterId.String(),
			Flops:           s.Flops,
			BfdState: &api.BfdPeerState{
				SessionState:                 bfdSessionStateToAPI(pconf.Bfd.State.SessionState),
				RemoteSessionState:           bfdSessionStateToAPI(pconf.Bfd.State.RemoteSessionState),
				LastFailureTime:              pconf.Bfd.State.LastFailureTime,
				FailureTransitions:           pconf.Bfd.State.FailureTransitions,
				LocalDiscriminator:           pconf.Bfd.State.LocalDiscriminator,
				RemoteDiscriminator:          pconf.Bfd.State.RemoteDiscriminator,
				LocalDiagnosticCode:          bfdDiagnosticCodeToAPI(pconf.Bfd.State.LocalDiagnosticCode),
				RemoteDiagnosticCode:         bfdDiagnosticCodeToAPI(pconf.Bfd.State.RemoteDiagnosticCode),
				RemoteMinimumReceiveInterval: pconf.Bfd.State.RemoteMinimumReceiveInterval,
				BfdAsync: &api.BfdAsyncCounters{
					TransmittedPackets: pconf.Bfd.State.BfdAsync.TransmittedPackets,
					ReceivedPackets:    pconf.Bfd.State.BfdAsync.ReceivedPackets,
				},
			},
		},
		EbgpMultihop: &api.EbgpMultihop{
			Enabled:     pconf.EbgpMultihop.Config.Enabled,
			MultihopTtl: uint32(pconf.EbgpMultihop.Config.MultihopTtl),
		},
		TtlSecurity: &api.TtlSecurity{
			Enabled: pconf.TtlSecurity.Config.Enabled,
			TtlMin:  uint32(pconf.TtlSecurity.Config.TtlMin),
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				ConnectRetry:           uint64(timer.Config.ConnectRetry),
				HoldTime:               uint64(timer.Config.HoldTime),
				KeepaliveInterval:      uint64(timer.Config.KeepaliveInterval),
				IdleHoldTimeAfterReset: uint64(timer.Config.IdleHoldTimeAfterReset),
			},
			State: &api.TimersState{
				KeepaliveInterval:  uint64(timer.State.KeepaliveInterval),
				NegotiatedHoldTime: uint64(timer.State.NegotiatedHoldTime),
				Uptime:             ProtoTimestamp(timer.State.Uptime),
				Downtime:           ProtoTimestamp(timer.State.Downtime),
			},
		},
		RouteReflector: &api.RouteReflector{
			RouteReflectorClient:    pconf.RouteReflector.Config.RouteReflectorClient,
			RouteReflectorClusterId: pconf.RouteReflector.State.RouteReflectorClusterId.String(),
		},
		RouteServer: &api.RouteServer{
			RouteServerClient: pconf.RouteServer.Config.RouteServerClient,
			SecondaryRoute:    pconf.RouteServer.Config.SecondaryRoute,
		},
		GracefulRestart: &api.GracefulRestart{
			Enabled:             pconf.GracefulRestart.Config.Enabled,
			RestartTime:         uint32(pconf.GracefulRestart.Config.RestartTime),
			HelperOnly:          pconf.GracefulRestart.Config.HelperOnly,
			DeferralTime:        uint32(pconf.GracefulRestart.Config.DeferralTime),
			NotificationEnabled: pconf.GracefulRestart.Config.NotificationEnabled,
			LonglivedEnabled:    pconf.GracefulRestart.Config.LongLivedEnabled,
			LocalRestarting:     pconf.GracefulRestart.State.LocalRestarting,
			PeerRestartTime:     uint32(pconf.GracefulRestart.State.PeerRestartTime),
			PeerRestarting:      pconf.GracefulRestart.State.PeerRestarting,
		},
		Transport: &api.Transport{
			RemotePort:    uint32(pconf.Transport.Config.RemotePort),
			LocalPort:     uint32(pconf.Transport.Config.LocalPort),
			LocalAddress:  localAddress.String(),
			PassiveMode:   pconf.Transport.Config.PassiveMode,
			BindInterface: pconf.Transport.Config.BindInterface,
			TcpMss:        uint32(pconf.Transport.Config.TcpMss),
			IpTos:         uint32(pconf.Transport.Config.IpTos),
		},
		AfiSafis: afiSafis,
		Bfd: &api.BfdPeerConfig{
			Enabled:                  pconf.Bfd.Config.Enabled,
			Port:                     uint32(pconf.Bfd.Config.Port),
			DesiredMinimumTxInterval: pconf.Bfd.Config.DesiredMinimumTxInterval,
			RequiredMinimumReceive:   pconf.Bfd.Config.RequiredMinimumReceive,
			DetectionMultiplier:      uint32(pconf.Bfd.Config.DetectionMultiplier),
		},
	}
}

func NewPeerGroupFromConfigStruct(pconf *PeerGroup) *api.PeerGroup {
	afiSafis := make([]*api.AfiSafi, 0, len(pconf.AfiSafis))
	for _, f := range pconf.AfiSafis {
		if afiSafi := newAfiSafiFromConfigStruct(&f); afiSafi != nil {
			afiSafi.AddPaths.Config.Receive = pconf.AddPaths.Config.Receive
			afiSafi.AddPaths.Config.SendMax = uint32(pconf.AddPaths.Config.SendMax)
			afiSafis = append(afiSafis, afiSafi)
		}
	}

	timer := pconf.Timers
	s := pconf.State
	return &api.PeerGroup{
		ApplyPolicy: newApplyPolicyFromConfigStruct(&pconf.ApplyPolicy),
		Conf: &api.PeerGroupConf{
			PeerAsn:             pconf.Config.PeerAs,
			LocalAsn:            pconf.Config.LocalAs,
			Type:                toPeerType(pconf.Config.PeerType),
			AuthPassword:        pconf.Config.AuthPassword,
			RouteFlapDamping:    pconf.Config.RouteFlapDamping,
			Description:         pconf.Config.Description,
			PeerGroupName:       pconf.Config.PeerGroupName,
			SendSoftwareVersion: pconf.Config.SendSoftwareVersion,
		},
		Info: &api.PeerGroupState{
			PeerAsn:       s.PeerAs,
			Type:          toPeerType(s.PeerType),
			TotalPaths:    s.TotalPaths,
			TotalPrefixes: s.TotalPrefixes,
		},
		EbgpMultihop: &api.EbgpMultihop{
			Enabled:     pconf.EbgpMultihop.Config.Enabled,
			MultihopTtl: uint32(pconf.EbgpMultihop.Config.MultihopTtl),
		},
		TtlSecurity: &api.TtlSecurity{
			Enabled: pconf.TtlSecurity.Config.Enabled,
			TtlMin:  uint32(pconf.TtlSecurity.Config.TtlMin),
		},
		Timers: &api.Timers{
			Config: &api.TimersConfig{
				ConnectRetry:           uint64(timer.Config.ConnectRetry),
				HoldTime:               uint64(timer.Config.HoldTime),
				KeepaliveInterval:      uint64(timer.Config.KeepaliveInterval),
				IdleHoldTimeAfterReset: uint64(timer.Config.IdleHoldTimeAfterReset),
			},
			State: &api.TimersState{
				KeepaliveInterval:  uint64(timer.State.KeepaliveInterval),
				NegotiatedHoldTime: uint64(timer.State.NegotiatedHoldTime),
				Uptime:             ProtoTimestamp(timer.State.Uptime),
				Downtime:           ProtoTimestamp(timer.State.Downtime),
			},
		},
		RouteReflector: &api.RouteReflector{
			RouteReflectorClient:    pconf.RouteReflector.Config.RouteReflectorClient,
			RouteReflectorClusterId: pconf.RouteReflector.Config.RouteReflectorClusterId.String(),
		},
		RouteServer: &api.RouteServer{
			RouteServerClient: pconf.RouteServer.Config.RouteServerClient,
			SecondaryRoute:    pconf.RouteServer.Config.SecondaryRoute,
		},
		GracefulRestart: &api.GracefulRestart{
			Enabled:             pconf.GracefulRestart.Config.Enabled,
			RestartTime:         uint32(pconf.GracefulRestart.Config.RestartTime),
			HelperOnly:          pconf.GracefulRestart.Config.HelperOnly,
			DeferralTime:        uint32(pconf.GracefulRestart.Config.DeferralTime),
			NotificationEnabled: pconf.GracefulRestart.Config.NotificationEnabled,
			LonglivedEnabled:    pconf.GracefulRestart.Config.LongLivedEnabled,
			LocalRestarting:     pconf.GracefulRestart.State.LocalRestarting,
		},
		Transport: &api.Transport{
			RemotePort:   uint32(pconf.Transport.Config.RemotePort),
			LocalAddress: pconf.Transport.Config.LocalAddress.String(),
			PassiveMode:  pconf.Transport.Config.PassiveMode,
			TcpMss:       uint32(pconf.Transport.Config.TcpMss),
			IpTos:        uint32(pconf.Transport.Config.IpTos),
		},
		AfiSafis: afiSafis,
		Bfd: &api.BfdPeerConfig{
			Enabled:                  pconf.Bfd.Config.Enabled,
			Port:                     uint32(pconf.Bfd.Config.Port),
			DesiredMinimumTxInterval: pconf.Bfd.Config.DesiredMinimumTxInterval,
			RequiredMinimumReceive:   pconf.Bfd.Config.RequiredMinimumReceive,
			DetectionMultiplier:      uint32(pconf.Bfd.Config.DetectionMultiplier),
		},
	}
}

func NewGlobalFromConfigStruct(c *Global) *api.Global {
	families := make([]uint32, 0, len(c.AfiSafis))
	for _, f := range c.AfiSafis {
		families = append(families, uint32(AfiSafiTypeToIntMap[f.Config.AfiSafiName]))
	}

	l := make([]string, 0, len(c.Config.LocalAddressList))
	for _, addr := range c.Config.LocalAddressList {
		l = append(l, addr.String())
	}

	return &api.Global{
		Asn:              c.Config.As,
		RouterId:         c.Config.RouterId.String(),
		ListenPort:       c.Config.Port,
		ListenAddresses:  l,
		Families:         families,
		UseMultiplePaths: c.UseMultiplePaths.Config.Enabled,
		RouteSelectionOptions: &api.RouteSelectionOptionsConfig{
			AlwaysCompareMed:         c.RouteSelectionOptions.Config.AlwaysCompareMed,
			IgnoreAsPathLength:       c.RouteSelectionOptions.Config.IgnoreAsPathLength,
			ExternalCompareRouterId:  c.RouteSelectionOptions.Config.ExternalCompareRouterId,
			AdvertiseInactiveRoutes:  c.RouteSelectionOptions.Config.AdvertiseInactiveRoutes,
			EnableAigp:               c.RouteSelectionOptions.Config.EnableAigp,
			IgnoreNextHopIgpMetric:   c.RouteSelectionOptions.Config.IgnoreNextHopIgpMetric,
			DisableBestPathSelection: c.RouteSelectionOptions.Config.DisableBestPathSelection,
		},
		DefaultRouteDistance: &api.DefaultRouteDistance{
			ExternalRouteDistance: uint32(c.DefaultRouteDistance.Config.ExternalRouteDistance),
			InternalRouteDistance: uint32(c.DefaultRouteDistance.Config.InternalRouteDistance),
		},
		Confederation: &api.Confederation{
			Enabled:      c.Confederation.Config.Enabled,
			Identifier:   c.Confederation.Config.Identifier,
			MemberAsList: c.Confederation.Config.MemberAsList,
		},
		GracefulRestart: &api.GracefulRestart{
			Enabled:             c.GracefulRestart.Config.Enabled,
			RestartTime:         uint32(c.GracefulRestart.Config.RestartTime),
			StaleRoutesTime:     uint32(c.GracefulRestart.Config.StaleRoutesTime),
			HelperOnly:          c.GracefulRestart.Config.HelperOnly,
			DeferralTime:        uint32(c.GracefulRestart.Config.DeferralTime),
			NotificationEnabled: c.GracefulRestart.Config.NotificationEnabled,
			LonglivedEnabled:    c.GracefulRestart.Config.LongLivedEnabled,
		},
	}
}

func newAPIPrefixFromConfigStruct(c Prefix) (*api.Prefix, error) {
	min, max, err := ParseMaskLength(c.IpPrefix.String(), c.MasklengthRange)
	if err != nil {
		return nil, err
	}
	return &api.Prefix{
		IpPrefix:      c.IpPrefix.String(),
		MaskLengthMin: uint32(min),
		MaskLengthMax: uint32(max),
	}, nil
}

func NewAPIDefinedSetsFromConfigStruct(t *DefinedSets) ([]*api.DefinedSet, error) {
	definedSets := make([]*api.DefinedSet, 0)

	for _, ps := range t.PrefixSets {
		prefixes := make([]*api.Prefix, 0)
		for _, p := range ps.PrefixList {
			ap, err := newAPIPrefixFromConfigStruct(p)
			if err != nil {
				return nil, err
			}
			prefixes = append(prefixes, ap)
		}
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_PREFIX,
			Name:        ps.PrefixSetName,
			Prefixes:    prefixes,
		})
	}

	for _, ns := range t.NeighborSets {
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_NEIGHBOR,
			Name:        ns.NeighborSetName,
			List:        ns.NeighborInfoList,
		})
	}

	bs := t.BgpDefinedSets
	for _, cs := range bs.CommunitySets {
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_COMMUNITY,
			Name:        cs.CommunitySetName,
			List:        cs.CommunityList,
		})
	}

	for _, es := range bs.ExtCommunitySets {
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_EXT_COMMUNITY,
			Name:        es.ExtCommunitySetName,
			List:        es.ExtCommunityList,
		})
	}

	for _, ls := range bs.LargeCommunitySets {
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_LARGE_COMMUNITY,
			Name:        ls.LargeCommunitySetName,
			List:        ls.LargeCommunityList,
		})
	}

	for _, as := range bs.AsPathSets {
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_DEFINED_TYPE_AS_PATH,
			Name:        as.AsPathSetName,
			List:        as.AsPathList,
		})
	}

	return definedSets, nil
}
