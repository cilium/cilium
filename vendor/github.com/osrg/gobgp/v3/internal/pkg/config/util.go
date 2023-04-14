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

package config

import (
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	tspb "google.golang.org/protobuf/types/known/timestamppb"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
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
func extractArray(intf interface{}) ([]interface{}, error) {
	if intf != nil {
		list, ok := intf.([]interface{})
		if ok {
			return list, nil
		}
		l, ok := intf.([]map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("invalid configuration: neither []interface{} nor []map[string]interface{}")
		}
		list = make([]interface{}, 0, len(l))
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
	if _, _, err := net.ParseCIDR(d.Config.Prefix); err != nil {
		return fmt.Errorf("invalid dynamic neighbor prefix %s", d.Config.Prefix)
	}
	return nil
}

func (n *Neighbor) IsConfederationMember(g *Global) bool {
	for _, member := range g.Confederation.Config.MemberAsList {
		if member == n.Config.PeerAs {
			return true
		}
	}
	return false
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

func (n *Neighbor) CreateRfMap() map[bgp.RouteFamily]bgp.BGPAddPathMode {
	rfMap := make(map[bgp.RouteFamily]bgp.BGPAddPathMode)
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

func (n *Neighbor) GetAfiSafi(family bgp.RouteFamily) *AfiSafi {
	for _, a := range n.AfiSafis {
		if string(a.Config.AfiSafiName) == family.String() {
			return &a
		}
	}
	return nil
}

func (n *Neighbor) ExtractNeighborAddress() (string, error) {
	addr := n.State.NeighborAddress
	if addr == "" {
		addr = n.Config.NeighborAddress
		if addr == "" {
			return "", fmt.Errorf("NeighborAddress is not configured")
		}
	}
	return addr, nil
}

func (n *Neighbor) IsAddPathReceiveEnabled(family bgp.RouteFamily) bool {
	for _, af := range n.AfiSafis {
		if af.State.Family == family {
			return af.AddPaths.State.Receive
		}
	}
	return false
}

type AfiSafis []AfiSafi

func (c AfiSafis) ToRfList() ([]bgp.RouteFamily, error) {
	rfs := make([]bgp.RouteFamily, 0, len(c))
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
		isAfiSafiChanged(n.AfiSafis, new.AfiSafis)
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
	if rf, err := bgp.GetRouteFamily(string(c.Config.AfiSafiName)); err == nil {
		return uint32(rf)
	}
	// Ignores invalid address family name
	return 0
}

func newAfiSafiConfigFromConfigStruct(c *AfiSafi) *api.AfiSafiConfig {
	rf := extractFamilyFromConfigAfiSafi(c)
	afi, safi := bgp.RouteFamilyToAfiSafi(bgp.RouteFamily(rf))
	return &api.AfiSafiConfig{
		Family:  &api.Family{Afi: api.Family_Afi(afi), Safi: api.Family_Safi(safi)},
		Enabled: c.Config.Enabled,
	}
}

func newApplyPolicyFromConfigStruct(c *ApplyPolicy) *api.ApplyPolicy {
	f := func(t DefaultPolicyType) api.RouteAction {
		if t == DEFAULT_POLICY_TYPE_ACCEPT_ROUTE {
			return api.RouteAction_ACCEPT
		} else if t == DEFAULT_POLICY_TYPE_REJECT_ROUTE {
			return api.RouteAction_REJECT
		}
		return api.RouteAction_NONE
	}
	applyPolicy := &api.ApplyPolicy{
		ImportPolicy: &api.PolicyAssignment{
			Direction:     api.PolicyDirection_IMPORT,
			DefaultAction: f(c.Config.DefaultImportPolicy),
		},
		ExportPolicy: &api.PolicyAssignment{
			Direction:     api.PolicyDirection_EXPORT,
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
	afi, safi := bgp.RouteFamilyToAfiSafi(bgp.RouteFamily(c.State.Family))
	return &api.PrefixLimit{
		Family:               &api.Family{Afi: api.Family_Afi(afi), Safi: api.Family_Safi(safi)},
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
	if pconf.Transport.State.LocalAddress != "" {
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
		removePrivate = api.RemovePrivate_REMOVE_ALL
	case REMOVE_PRIVATE_AS_OPTION_REPLACE:
		removePrivate = api.RemovePrivate_REPLACE
	}
	return &api.Peer{
		ApplyPolicy: newApplyPolicyFromConfigStruct(&pconf.ApplyPolicy),
		Conf: &api.PeerConf{
			NeighborAddress:     pconf.Config.NeighborAddress,
			PeerAsn:             pconf.Config.PeerAs,
			LocalAsn:            pconf.Config.LocalAs,
			Type:                api.PeerType(pconf.Config.PeerType.ToInt()),
			AuthPassword:        pconf.Config.AuthPassword,
			RouteFlapDamping:    pconf.Config.RouteFlapDamping,
			Description:         pconf.Config.Description,
			PeerGroup:           pconf.Config.PeerGroup,
			NeighborInterface:   pconf.Config.NeighborInterface,
			Vrf:                 pconf.Config.Vrf,
			AllowOwnAsn:         uint32(pconf.AsPathOptions.Config.AllowOwnAs),
			RemovePrivate:       removePrivate,
			ReplacePeerAsn:      pconf.AsPathOptions.Config.ReplacePeerAs,
			AdminDown:           pconf.Config.AdminDown,
			SendSoftwareVersion: pconf.Config.SendSoftwareVersion,
		},
		State: &api.PeerState{
			SessionState: api.PeerState_SessionState(api.PeerState_SessionState_value[strings.ToUpper(string(s.SessionState))]),
			AdminState:   api.PeerState_AdminState(s.AdminState.ToInt()),
			Messages: &api.Messages{
				Received: &api.Message{
					Notification:   s.Messages.Received.Notification,
					Update:         s.Messages.Received.Update,
					Open:           s.Messages.Received.Open,
					Keepalive:      s.Messages.Received.Keepalive,
					Refresh:        s.Messages.Received.Refresh,
					Discarded:      s.Messages.Received.Discarded,
					Total:          s.Messages.Received.Total,
					WithdrawUpdate: uint64(s.Messages.Received.WithdrawUpdate),
					WithdrawPrefix: uint64(s.Messages.Received.WithdrawPrefix),
				},
				Sent: &api.Message{
					Notification: s.Messages.Sent.Notification,
					Update:       s.Messages.Sent.Update,
					Open:         s.Messages.Sent.Open,
					Keepalive:    s.Messages.Sent.Keepalive,
					Refresh:      s.Messages.Sent.Refresh,
					Discarded:    s.Messages.Sent.Discarded,
					Total:        s.Messages.Sent.Total,
				},
			},
			PeerAsn:         s.PeerAs,
			LocalAsn:        s.LocalAs,
			Type:            api.PeerType(s.PeerType.ToInt()),
			NeighborAddress: pconf.State.NeighborAddress,
			Queues:          &api.Queues{},
			RemoteCap:       remoteCap,
			LocalCap:        localCap,
			RouterId:        s.RemoteRouterId,
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
			RouteReflectorClusterId: string(pconf.RouteReflector.State.RouteReflectorClusterId),
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
			RemotePort:    uint32(pconf.Transport.Config.RemotePort),
			LocalPort:     uint32(pconf.Transport.Config.LocalPort),
			LocalAddress:  localAddress,
			PassiveMode:   pconf.Transport.Config.PassiveMode,
			BindInterface: pconf.Transport.Config.BindInterface,
		},
		AfiSafis: afiSafis,
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
			PeerAsn:          pconf.Config.PeerAs,
			LocalAsn:         pconf.Config.LocalAs,
			Type:             api.PeerType(pconf.Config.PeerType.ToInt()),
			AuthPassword:     pconf.Config.AuthPassword,
			RouteFlapDamping: pconf.Config.RouteFlapDamping,
			Description:      pconf.Config.Description,
			PeerGroupName:    pconf.Config.PeerGroupName,
		},
		Info: &api.PeerGroupState{
			PeerAsn:       s.PeerAs,
			Type:          api.PeerType(s.PeerType.ToInt()),
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
			RouteReflectorClusterId: string(pconf.RouteReflector.Config.RouteReflectorClusterId),
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
			LocalAddress: pconf.Transport.Config.LocalAddress,
			PassiveMode:  pconf.Transport.Config.PassiveMode,
		},
		AfiSafis: afiSafis,
	}
}

func NewGlobalFromConfigStruct(c *Global) *api.Global {
	families := make([]uint32, 0, len(c.AfiSafis))
	for _, f := range c.AfiSafis {
		families = append(families, uint32(AfiSafiTypeToIntMap[f.Config.AfiSafiName]))
	}

	applyPolicy := newApplyPolicyFromConfigStruct(&c.ApplyPolicy)

	return &api.Global{
		Asn:              c.Config.As,
		RouterId:         c.Config.RouterId,
		ListenPort:       c.Config.Port,
		ListenAddresses:  c.Config.LocalAddressList,
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
		ApplyPolicy: applyPolicy,
	}
}

func newAPIPrefixFromConfigStruct(c Prefix) (*api.Prefix, error) {
	min, max, err := ParseMaskLength(c.IpPrefix, c.MasklengthRange)
	if err != nil {
		return nil, err
	}
	return &api.Prefix{
		IpPrefix:      c.IpPrefix,
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
			DefinedType: api.DefinedType_PREFIX,
			Name:        ps.PrefixSetName,
			Prefixes:    prefixes,
		})
	}

	for _, ns := range t.NeighborSets {
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_NEIGHBOR,
			Name:        ns.NeighborSetName,
			List:        ns.NeighborInfoList,
		})
	}

	bs := t.BgpDefinedSets
	for _, cs := range bs.CommunitySets {
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_COMMUNITY,
			Name:        cs.CommunitySetName,
			List:        cs.CommunityList,
		})
	}

	for _, es := range bs.ExtCommunitySets {
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_EXT_COMMUNITY,
			Name:        es.ExtCommunitySetName,
			List:        es.ExtCommunityList,
		})
	}

	for _, ls := range bs.LargeCommunitySets {
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_LARGE_COMMUNITY,
			Name:        ls.LargeCommunitySetName,
			List:        ls.LargeCommunityList,
		})
	}

	for _, as := range bs.AsPathSets {
		definedSets = append(definedSets, &api.DefinedSet{
			DefinedType: api.DefinedType_AS_PATH,
			Name:        as.AsPathSetName,
			List:        as.AsPathList,
		})
	}

	return definedSets, nil
}
