package config

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"reflect"
	"strconv"

	"github.com/osrg/gobgp/v3/internal/pkg/version"
	"github.com/osrg/gobgp/v3/internal/pkg/zebra"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/packet/bmp"
	"github.com/osrg/gobgp/v3/pkg/packet/rtr"
	"github.com/spf13/viper"
)

const (
	DEFAULT_HOLDTIME                  = 90
	DEFAULT_IDLE_HOLDTIME_AFTER_RESET = 30
	DEFAULT_CONNECT_RETRY             = 120
)

var forcedOverwrittenConfig = []string{
	"neighbor.config.peer-as",
	"neighbor.timers.config.minimum-advertisement-interval",
}

var configuredFields map[string]interface{}

func RegisterConfiguredFields(addr string, n interface{}) {
	if configuredFields == nil {
		configuredFields = make(map[string]interface{})
	}
	configuredFields[addr] = n
}

func defaultAfiSafi(typ AfiSafiType, enable bool) AfiSafi {
	return AfiSafi{
		Config: AfiSafiConfig{
			AfiSafiName: typ,
			Enabled:     enable,
		},
		State: AfiSafiState{
			AfiSafiName: typ,
			Family:      bgp.AddressFamilyValueMap[string(typ)],
		},
	}
}

func SetDefaultNeighborConfigValues(n *Neighbor, pg *PeerGroup, g *Global) error {
	// Determines this function is called against the same Neighbor struct,
	// and if already called, returns immediately.
	if n.State.LocalAs != 0 {
		return nil
	}

	return setDefaultNeighborConfigValuesWithViper(nil, n, g, pg)
}

func setDefaultNeighborConfigValuesWithViper(v *viper.Viper, n *Neighbor, g *Global, pg *PeerGroup) error {
	if n == nil {
		return fmt.Errorf("neighbor config is nil")
	}
	if g == nil {
		return fmt.Errorf("global config is nil")
	}

	if v == nil {
		v = viper.New()
	}

	if pg != nil {
		if err := OverwriteNeighborConfigWithPeerGroup(n, pg); err != nil {
			return err
		}
	}

	if n.Config.LocalAs == 0 {
		n.Config.LocalAs = g.Config.As
		if !g.Confederation.Config.Enabled || n.IsConfederation(g) {
			n.Config.LocalAs = g.Config.As
		} else {
			n.Config.LocalAs = g.Confederation.Config.Identifier
		}
	}
	n.State.LocalAs = n.Config.LocalAs

	if n.Config.PeerAs != n.Config.LocalAs {
		n.Config.PeerType = PEER_TYPE_EXTERNAL
		n.State.PeerType = PEER_TYPE_EXTERNAL
		n.State.RemovePrivateAs = n.Config.RemovePrivateAs
		n.AsPathOptions.State.ReplacePeerAs = n.AsPathOptions.Config.ReplacePeerAs
	} else {
		n.Config.PeerType = PEER_TYPE_INTERNAL
		n.State.PeerType = PEER_TYPE_INTERNAL
		if string(n.Config.RemovePrivateAs) != "" {
			return fmt.Errorf("can't set remove-private-as for iBGP peer")
		}
		if n.AsPathOptions.Config.ReplacePeerAs {
			return fmt.Errorf("can't set replace-peer-as for iBGP peer")
		}
	}

	if n.State.NeighborAddress == "" {
		n.State.NeighborAddress = n.Config.NeighborAddress
	}

	n.State.PeerAs = n.Config.PeerAs
	n.AsPathOptions.State.AllowOwnAs = n.AsPathOptions.Config.AllowOwnAs

	if !v.IsSet("neighbor.error-handling.config.treat-as-withdraw") {
		n.ErrorHandling.Config.TreatAsWithdraw = true
	}

	if !v.IsSet("neighbor.timers.config.connect-retry") && n.Timers.Config.ConnectRetry == 0 {
		n.Timers.Config.ConnectRetry = float64(DEFAULT_CONNECT_RETRY)
	}
	if !v.IsSet("neighbor.timers.config.hold-time") && n.Timers.Config.HoldTime == 0 {
		n.Timers.Config.HoldTime = float64(DEFAULT_HOLDTIME)
	}
	if !v.IsSet("neighbor.timers.config.keepalive-interval") && n.Timers.Config.KeepaliveInterval == 0 {
		n.Timers.Config.KeepaliveInterval = n.Timers.Config.HoldTime / 3
	}
	if !v.IsSet("neighbor.timers.config.idle-hold-time-after-reset") && n.Timers.Config.IdleHoldTimeAfterReset == 0 {
		n.Timers.Config.IdleHoldTimeAfterReset = float64(DEFAULT_IDLE_HOLDTIME_AFTER_RESET)
	}

	if n.Config.NeighborInterface != "" {
		if n.RouteServer.Config.RouteServerClient {
			return fmt.Errorf("configuring route server client as unnumbered peer is not supported")
		}
		addr, err := GetIPv6LinkLocalNeighborAddress(n.Config.NeighborInterface)
		if err != nil {
			return err
		}
		n.State.NeighborAddress = addr
	}

	if n.Transport.Config.LocalAddress == "" {
		if n.State.NeighborAddress == "" {
			return fmt.Errorf("no neighbor address/interface specified")
		}
		ipAddr, err := net.ResolveIPAddr("ip", n.State.NeighborAddress)
		if err != nil {
			return err
		}
		localAddress := "0.0.0.0"
		if ipAddr.IP.To4() == nil {
			localAddress = "::"
			if ipAddr.Zone != "" {
				localAddress, err = getIPv6LinkLocalAddress(ipAddr.Zone)
				if err != nil {
					return err
				}
			}
		}
		n.Transport.Config.LocalAddress = localAddress
	}

	if len(n.AfiSafis) == 0 {
		if n.Config.NeighborInterface != "" {
			n.AfiSafis = []AfiSafi{
				defaultAfiSafi(AFI_SAFI_TYPE_IPV4_UNICAST, true),
				defaultAfiSafi(AFI_SAFI_TYPE_IPV6_UNICAST, true),
			}
		} else if ipAddr, err := net.ResolveIPAddr("ip", n.State.NeighborAddress); err != nil {
			return fmt.Errorf("invalid neighbor address: %s", n.State.NeighborAddress)
		} else if ipAddr.IP.To4() != nil {
			n.AfiSafis = []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV4_UNICAST, true)}
		} else {
			n.AfiSafis = []AfiSafi{defaultAfiSafi(AFI_SAFI_TYPE_IPV6_UNICAST, true)}
		}
		for i := range n.AfiSafis {
			n.AfiSafis[i].AddPaths.Config.Receive = n.AddPaths.Config.Receive
			n.AfiSafis[i].AddPaths.State.Receive = n.AddPaths.Config.Receive
			n.AfiSafis[i].AddPaths.Config.SendMax = n.AddPaths.Config.SendMax
			n.AfiSafis[i].AddPaths.State.SendMax = n.AddPaths.Config.SendMax
		}
	} else {
		afs, err := extractArray(v.Get("neighbor.afi-safis"))
		if err != nil {
			return err
		}
		for i := range n.AfiSafis {
			vv := viper.New()
			if len(afs) > i {
				vv.Set("afi-safi", afs[i])
			}
			rf, err := bgp.GetRouteFamily(string(n.AfiSafis[i].Config.AfiSafiName))
			if err != nil {
				return err
			}
			n.AfiSafis[i].State.Family = rf
			n.AfiSafis[i].State.AfiSafiName = n.AfiSafis[i].Config.AfiSafiName
			if !vv.IsSet("afi-safi.config.enabled") {
				n.AfiSafis[i].Config.Enabled = true
			}
			n.AfiSafis[i].MpGracefulRestart.State.Enabled = n.AfiSafis[i].MpGracefulRestart.Config.Enabled
			if !vv.IsSet("afi-safi.add-paths.config.receive") {
				if n.AddPaths.Config.Receive {
					n.AfiSafis[i].AddPaths.Config.Receive = n.AddPaths.Config.Receive
				}
			}
			n.AfiSafis[i].AddPaths.State.Receive = n.AfiSafis[i].AddPaths.Config.Receive
			if !vv.IsSet("afi-safi.add-paths.config.send-max") {
				if n.AddPaths.Config.SendMax != 0 {
					n.AfiSafis[i].AddPaths.Config.SendMax = n.AddPaths.Config.SendMax
				}
			}
			n.AfiSafis[i].AddPaths.State.SendMax = n.AfiSafis[i].AddPaths.Config.SendMax
		}
	}

	n.State.Description = n.Config.Description
	n.State.AdminDown = n.Config.AdminDown

	if n.GracefulRestart.Config.Enabled {
		if !v.IsSet("neighbor.graceful-restart.config.restart-time") && n.GracefulRestart.Config.RestartTime == 0 {
			// RFC 4724 4. Operation
			// A suggested default for the Restart Time is a value less than or
			// equal to the HOLDTIME carried in the OPEN.
			n.GracefulRestart.Config.RestartTime = uint16(n.Timers.Config.HoldTime)
		}
		if !v.IsSet("neighbor.graceful-restart.config.deferral-time") && n.GracefulRestart.Config.DeferralTime == 0 {
			// RFC 4724 4.1. Procedures for the Restarting Speaker
			// The value of this timer should be large
			// enough, so as to provide all the peers of the Restarting Speaker with
			// enough time to send all the routes to the Restarting Speaker
			n.GracefulRestart.Config.DeferralTime = uint16(360)
		}
	}

	if n.EbgpMultihop.Config.Enabled {
		if n.TtlSecurity.Config.Enabled {
			return fmt.Errorf("ebgp-multihop and ttl-security are mututally exclusive")
		}
		if n.EbgpMultihop.Config.MultihopTtl == 0 {
			n.EbgpMultihop.Config.MultihopTtl = 255
		}
	} else if n.TtlSecurity.Config.Enabled {
		if n.TtlSecurity.Config.TtlMin == 0 {
			n.TtlSecurity.Config.TtlMin = 255
		}
	}

	if n.RouteReflector.Config.RouteReflectorClient {
		if n.RouteReflector.Config.RouteReflectorClusterId == "" {
			n.RouteReflector.State.RouteReflectorClusterId = RrClusterIdType(g.Config.RouterId)
		} else {
			id := string(n.RouteReflector.Config.RouteReflectorClusterId)
			if ip := net.ParseIP(id).To4(); ip != nil {
				n.RouteReflector.State.RouteReflectorClusterId = n.RouteReflector.Config.RouteReflectorClusterId
			} else if num, err := strconv.ParseUint(id, 10, 32); err == nil {
				ip = make(net.IP, 4)
				binary.BigEndian.PutUint32(ip, uint32(num))
				n.RouteReflector.State.RouteReflectorClusterId = RrClusterIdType(ip.String())
			} else {
				return fmt.Errorf("route-reflector-cluster-id should be specified as IPv4 address or 32-bit unsigned integer")
			}
		}
	}

	return nil
}

func SetDefaultGlobalConfigValues(g *Global) error {
	if len(g.AfiSafis) == 0 {
		g.AfiSafis = []AfiSafi{}
		for k := range AfiSafiTypeToIntMap {
			g.AfiSafis = append(g.AfiSafis, defaultAfiSafi(k, true))
		}
	}

	if g.Config.Port == 0 {
		g.Config.Port = bgp.BGP_PORT
	}

	if len(g.Config.LocalAddressList) == 0 {
		g.Config.LocalAddressList = []string{"0.0.0.0", "::"}
	}
	return nil
}

func setDefaultVrfConfigValues(v *Vrf) error {
	if v == nil {
		return fmt.Errorf("cannot set default values for nil vrf config")
	}

	if v.Config.Name == "" {
		return fmt.Errorf("specify vrf name")
	}

	_, err := bgp.ParseRouteDistinguisher(v.Config.Rd)
	if err != nil {
		return fmt.Errorf("invalid rd for vrf %s: %s", v.Config.Name, v.Config.Rd)
	}

	if len(v.Config.ImportRtList) == 0 {
		v.Config.ImportRtList = v.Config.BothRtList
	}
	for _, rtString := range v.Config.ImportRtList {
		_, err := bgp.ParseRouteTarget(rtString)
		if err != nil {
			return fmt.Errorf("invalid import rt for vrf %s: %s", v.Config.Name, rtString)
		}
	}

	if len(v.Config.ExportRtList) == 0 {
		v.Config.ExportRtList = v.Config.BothRtList
	}
	for _, rtString := range v.Config.ExportRtList {
		_, err := bgp.ParseRouteTarget(rtString)
		if err != nil {
			return fmt.Errorf("invalid export rt for vrf %s: %s", v.Config.Name, rtString)
		}
	}

	return nil
}

func SetDefaultConfigValues(b *BgpConfigSet) error {
	return setDefaultConfigValuesWithViper(nil, b)
}

func setDefaultPolicyConfigValuesWithViper(v *viper.Viper, p *PolicyDefinition) error {
	stmts, err := extractArray(v.Get("policy.statements"))
	if err != nil {
		return err
	}
	for i := range p.Statements {
		vv := viper.New()
		if len(stmts) > i {
			vv.Set("statement", stmts[i])
		}
		if !vv.IsSet("statement.actions.route-disposition") {
			p.Statements[i].Actions.RouteDisposition = ROUTE_DISPOSITION_NONE
		}
	}
	return nil
}

func setDefaultConfigValuesWithViper(v *viper.Viper, b *BgpConfigSet) error {
	if v == nil {
		v = viper.New()
	}

	if err := SetDefaultGlobalConfigValues(&b.Global); err != nil {
		return err
	}

	for idx, server := range b.BmpServers {
		if server.Config.SysName == "" {
			server.Config.SysName = "GoBGP"
		}
		if server.Config.SysDescr == "" {
			server.Config.SysDescr = version.Version()
		}
		if server.Config.Port == 0 {
			server.Config.Port = bmp.BMP_DEFAULT_PORT
		}
		if server.Config.RouteMonitoringPolicy == "" {
			server.Config.RouteMonitoringPolicy = BMP_ROUTE_MONITORING_POLICY_TYPE_PRE_POLICY
		}
		// statistics-timeout is uint16 value and implicitly less than 65536
		if server.Config.StatisticsTimeout != 0 && server.Config.StatisticsTimeout < 15 {
			return fmt.Errorf("too small statistics-timeout value: %d", server.Config.StatisticsTimeout)
		}
		b.BmpServers[idx] = server
	}

	vrfNames := make(map[string]struct{})
	vrfIDs := make(map[uint32]struct{})
	for idx, vrf := range b.Vrfs {
		if err := setDefaultVrfConfigValues(&vrf); err != nil {
			return err
		}

		if _, ok := vrfNames[vrf.Config.Name]; ok {
			return fmt.Errorf("duplicated vrf name: %s", vrf.Config.Name)
		}
		vrfNames[vrf.Config.Name] = struct{}{}

		if vrf.Config.Id != 0 {
			if _, ok := vrfIDs[vrf.Config.Id]; ok {
				return fmt.Errorf("duplicated vrf id: %d", vrf.Config.Id)
			}
			vrfIDs[vrf.Config.Id] = struct{}{}
		}

		b.Vrfs[idx] = vrf
	}
	// Auto assign VRF identifier
	for idx, vrf := range b.Vrfs {
		if vrf.Config.Id == 0 {
			for id := uint32(1); id < math.MaxUint32; id++ {
				if _, ok := vrfIDs[id]; !ok {
					vrf.Config.Id = id
					vrfIDs[id] = struct{}{}
					break
				}
			}
		}
		b.Vrfs[idx] = vrf
	}

	if b.Zebra.Config.Url == "" {
		b.Zebra.Config.Url = "unix:/var/run/quagga/zserv.api"
	}
	if b.Zebra.Config.Version < zebra.MinZapiVer {
		b.Zebra.Config.Version = zebra.MinZapiVer
	} else if b.Zebra.Config.Version > zebra.MaxZapiVer {
		b.Zebra.Config.Version = zebra.MaxZapiVer
	}

	if !v.IsSet("zebra.config.nexthop-trigger-enable") && !b.Zebra.Config.NexthopTriggerEnable && b.Zebra.Config.Version > 2 {
		b.Zebra.Config.NexthopTriggerEnable = true
	}
	if b.Zebra.Config.NexthopTriggerDelay == 0 {
		b.Zebra.Config.NexthopTriggerDelay = 5
	}

	list, err := extractArray(v.Get("neighbors"))
	if err != nil {
		return err
	}

	for idx, n := range b.Neighbors {
		vv := viper.New()
		if len(list) > idx {
			vv.Set("neighbor", list[idx])
		}

		pg, err := b.getPeerGroup(n.Config.PeerGroup)
		if err != nil {
			return nil
		}

		if pg != nil {
			identifier := vv.Get("neighbor.config.neighbor-address")
			if identifier == nil {
				identifier = vv.Get("neighbor.config.neighbor-interface")
			}
			RegisterConfiguredFields(identifier.(string), list[idx])
		}

		if err := setDefaultNeighborConfigValuesWithViper(vv, &n, &b.Global, pg); err != nil {
			return err
		}
		b.Neighbors[idx] = n
	}

	for _, d := range b.DynamicNeighbors {
		if err := d.validate(b); err != nil {
			return err
		}
	}

	for idx, r := range b.RpkiServers {
		if r.Config.Port == 0 {
			b.RpkiServers[idx].Config.Port = rtr.RPKI_DEFAULT_PORT
		}
	}

	list, err = extractArray(v.Get("policy-definitions"))
	if err != nil {
		return err
	}

	for idx, p := range b.PolicyDefinitions {
		vv := viper.New()
		if len(list) > idx {
			vv.Set("policy", list[idx])
		}
		if err := setDefaultPolicyConfigValuesWithViper(vv, &p); err != nil {
			return err
		}
		b.PolicyDefinitions[idx] = p
	}

	return nil
}

func OverwriteNeighborConfigWithPeerGroup(c *Neighbor, pg *PeerGroup) error {
	v := viper.New()

	val, ok := configuredFields[c.Config.NeighborAddress]
	if ok {
		v.Set("neighbor", val)
	} else {
		v.Set("neighbor.config.peer-group", c.Config.PeerGroup)
	}

	overwriteConfig(&c.Config, &pg.Config, "neighbor.config", v)
	overwriteConfig(&c.Timers.Config, &pg.Timers.Config, "neighbor.timers.config", v)
	overwriteConfig(&c.Transport.Config, &pg.Transport.Config, "neighbor.transport.config", v)
	overwriteConfig(&c.ErrorHandling.Config, &pg.ErrorHandling.Config, "neighbor.error-handling.config", v)
	overwriteConfig(&c.LoggingOptions.Config, &pg.LoggingOptions.Config, "neighbor.logging-options.config", v)
	overwriteConfig(&c.EbgpMultihop.Config, &pg.EbgpMultihop.Config, "neighbor.ebgp-multihop.config", v)
	overwriteConfig(&c.RouteReflector.Config, &pg.RouteReflector.Config, "neighbor.route-reflector.config", v)
	overwriteConfig(&c.AsPathOptions.Config, &pg.AsPathOptions.Config, "neighbor.as-path-options.config", v)
	overwriteConfig(&c.AddPaths.Config, &pg.AddPaths.Config, "neighbor.add-paths.config", v)
	overwriteConfig(&c.GracefulRestart.Config, &pg.GracefulRestart.Config, "neighbor.gradeful-restart.config", v)
	overwriteConfig(&c.ApplyPolicy.Config, &pg.ApplyPolicy.Config, "neighbor.apply-policy.config", v)
	overwriteConfig(&c.UseMultiplePaths.Config, &pg.UseMultiplePaths.Config, "neighbor.use-multiple-paths.config", v)
	overwriteConfig(&c.RouteServer.Config, &pg.RouteServer.Config, "neighbor.route-server.config", v)
	overwriteConfig(&c.TtlSecurity.Config, &pg.TtlSecurity.Config, "neighbor.ttl-security.config", v)

	if !v.IsSet("neighbor.afi-safis") {
		c.AfiSafis = append([]AfiSafi{}, pg.AfiSafis...)
	}

	return nil
}

func overwriteConfig(c, pg interface{}, tagPrefix string, v *viper.Viper) {
	nValue := reflect.Indirect(reflect.ValueOf(c))
	nType := reflect.Indirect(nValue).Type()
	pgValue := reflect.Indirect(reflect.ValueOf(pg))
	pgType := reflect.Indirect(pgValue).Type()

	for i := 0; i < pgType.NumField(); i++ {
		field := pgType.Field(i).Name
		tag := tagPrefix + "." + nType.Field(i).Tag.Get("mapstructure")
		if func() bool {
			for _, t := range forcedOverwrittenConfig {
				if t == tag {
					return true
				}
			}
			return false
		}() || !v.IsSet(tag) {
			nValue.FieldByName(field).Set(pgValue.FieldByName(field))
		}
	}
}
