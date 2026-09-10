package config

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/internal/pkg/table"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/config/oc"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	"github.com/osrg/gobgp/v4/pkg/server"
)

// ReadConfigFile parses a config file into a BgpConfigSet which can be applied
// using InitialConfig and UpdateConfig.
func ReadConfigFile(configFile, configType string) (*oc.BgpConfigSet, error) {
	return oc.ReadConfigfile(configFile, configType)
}

// WatchConfigFile calls the callback function anytime an update to the
// config file is detected.
func WatchConfigFile(configFile, configType string, callBack func()) {
	oc.WatchConfigFile(configFile, configType, callBack)
}

const (
	stopOnConfigError     = true
	continueOnConfigError = false
)

func marshalRouteTargets(l []string) ([]*api.RouteTarget, error) {
	rtList := make([]*api.RouteTarget, 0, len(l))
	for _, rtString := range l {
		rt, err := bgp.ParseRouteTarget(rtString)
		if err != nil {
			return nil, err
		}
		a, err := apiutil.MarshalRT(rt)
		if err != nil {
			return nil, err
		}
		rtList = append(rtList, a)
	}
	return rtList, nil
}

func assignGlobalpolicy(ctx context.Context, bgpServer *server.BgpServer, a *oc.ApplyPolicyConfig, stopOnError bool) error {
	toDefaultTable := func(r oc.DefaultPolicyType) table.RouteType {
		var def table.RouteType
		switch r {
		case oc.DEFAULT_POLICY_TYPE_ACCEPT_ROUTE:
			def = table.ROUTE_TYPE_ACCEPT
		case oc.DEFAULT_POLICY_TYPE_REJECT_ROUTE:
			def = table.ROUTE_TYPE_REJECT
		}
		return def
	}
	toPolicies := func(r []string) []*table.Policy {
		p := make([]*table.Policy, 0, len(r))
		for _, n := range r {
			p = append(p, &table.Policy{
				Name: n,
			})
		}
		return p
	}

	def := toDefaultTable(a.DefaultImportPolicy)
	ps := toPolicies(a.ImportPolicyList)
	if err := bgpServer.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
		Assignment: table.NewAPIPolicyAssignmentFromTableStruct(&table.PolicyAssignment{
			Name:     table.GLOBAL_RIB_NAME,
			Type:     table.POLICY_DIRECTION_IMPORT,
			Policies: ps,
			Default:  def,
		}),
	}); err != nil {
		bgpServer.Log().Error("failed to set policy assignment",
			slog.String("Topic", "config"),
			slog.String("Direction", table.POLICY_DIRECTION_IMPORT.String()),
			slog.Any("Error", err),
		)
		if stopOnError {
			return fmt.Errorf("failed to set policy assignment: %w", err)
		}
	}

	def = toDefaultTable(a.DefaultExportPolicy)
	ps = toPolicies(a.ExportPolicyList)
	if err := bgpServer.SetPolicyAssignment(ctx, &api.SetPolicyAssignmentRequest{
		Assignment: table.NewAPIPolicyAssignmentFromTableStruct(&table.PolicyAssignment{
			Name:     table.GLOBAL_RIB_NAME,
			Type:     table.POLICY_DIRECTION_EXPORT,
			Policies: ps,
			Default:  def,
		}),
	}); err != nil {
		bgpServer.Log().Error("failed to set policy assignment",
			slog.String("Topic", "config"),
			slog.String("Direction", table.POLICY_DIRECTION_EXPORT.String()),
			slog.Any("Error", err),
		)
		if stopOnError {
			return fmt.Errorf("failed to set policy assignment: %w", err)
		}
	}

	return nil
}

func addPeerGroups(ctx context.Context, bgpServer *server.BgpServer, addedPg []oc.PeerGroup, stopOnError bool) error {
	for _, pg := range addedPg {
		bgpServer.Log().Info("add peer group",
			slog.String("Topic", "config"),
			slog.String("Key", pg.Config.PeerGroupName),
		)

		err := bgpServer.AddPeerGroup(ctx, &api.AddPeerGroupRequest{
			PeerGroup: oc.NewPeerGroupFromConfigStruct(&pg),
		})
		if err != nil {
			bgpServer.Log().Error("failed to add peer group",
				slog.String("Topic", "config"),
				slog.String("Key", pg.Config.PeerGroupName),
				slog.Any("Error", err))
			if stopOnError {
				return fmt.Errorf("failed to add peer group: %w", err)
			}
		}
	}

	return nil
}

func deletePeerGroups(ctx context.Context, bgpServer *server.BgpServer, deletedPg []oc.PeerGroup) {
	for _, pg := range deletedPg {
		bgpServer.Log().Info("delete peer group",
			slog.String("Topic", "config"),
			slog.String("Key", pg.Config.PeerGroupName),
		)
		err := bgpServer.DeletePeerGroup(ctx, &api.DeletePeerGroupRequest{
			Name: pg.Config.PeerGroupName,
		})
		if err != nil {
			bgpServer.Log().Error("failed to delete peer group",
				slog.String("Topic", "config"),
				slog.String("Key", pg.Config.PeerGroupName),
				slog.Any("Error", err),
			)
		}
	}
}

func updatePeerGroups(ctx context.Context, bgpServer *server.BgpServer, updatedPg []oc.PeerGroup) bool {
	needsSoftResetIn := false
	for _, pg := range updatedPg {
		bgpServer.Log().Info("update peer group",
			slog.String("Topic", "config"),
			slog.String("Key", pg.Config.PeerGroupName),
		)
		u, err := bgpServer.UpdatePeerGroup(ctx, &api.UpdatePeerGroupRequest{
			PeerGroup: oc.NewPeerGroupFromConfigStruct(&pg),
		})
		if err != nil {
			bgpServer.Log().Error("failed to update peer group",
				slog.String("Topic", "config"),
				slog.String("Key", pg.Config.PeerGroupName),
				slog.Any("Error", err),
			)
			continue
		}
		needsSoftResetIn = needsSoftResetIn || u.NeedsSoftResetIn
	}

	return needsSoftResetIn
}

func addDynamicNeighbors(ctx context.Context, bgpServer *server.BgpServer, dynamicNeighbors []oc.DynamicNeighbor, stopOnError bool) error {
	for _, dn := range dynamicNeighbors {
		bgpServer.Log().Info("add dynamic neighbor to peer group",
			slog.String("Topic", "config"),
			slog.String("Key", dn.Config.PeerGroup),
			slog.String("Prefix", dn.Config.Prefix.String()),
		)
		err := bgpServer.AddDynamicNeighbor(ctx, &api.AddDynamicNeighborRequest{
			DynamicNeighbor: &api.DynamicNeighbor{
				Prefix:    dn.Config.Prefix.String(),
				PeerGroup: dn.Config.PeerGroup,
			},
		})
		if err != nil {
			bgpServer.Log().Error("failed to add dynamic neighbor to peer group",
				slog.String("Topic", "config"),
				slog.String("Key", dn.Config.PeerGroup),
				slog.String("Prefix", dn.Config.Prefix.String()),
				slog.Any("Error", err),
			)
			if stopOnError {
				return fmt.Errorf("failed to add dynamic neighbor to peer group: %w", err)
			}
		}
	}

	return nil
}

func addNeighbors(ctx context.Context, bgpServer *server.BgpServer, added []oc.Neighbor, stopOnError bool) error {
	for _, p := range added {
		bgpServer.Log().Info("add peer",
			slog.String("Topic", "config"),
			slog.String("Key", p.State.NeighborAddress.String()),
		)
		err := bgpServer.AddPeer(ctx, &api.AddPeerRequest{
			Peer: oc.NewPeerFromConfigStruct(&p),
		})
		if err != nil {
			bgpServer.Log().Error("failed to add peer",
				slog.String("Topic", "config"),
				slog.String("Key", p.State.NeighborAddress.String()),
				slog.Any("Error", err))
			if stopOnError {
				return fmt.Errorf("failed to add peer: %w", err)
			}
		}
	}

	return nil
}

func deleteNeighbors(ctx context.Context, bgpServer *server.BgpServer, deleted []oc.Neighbor) {
	for _, p := range deleted {
		bgpServer.Log().Info("delete peer",
			slog.String("Topic", "config"),
			slog.String("Key", p.State.NeighborAddress.String()),
		)
		err := bgpServer.DeletePeer(ctx, &api.DeletePeerRequest{
			Address: p.State.NeighborAddress.String(),
		})
		if err != nil {
			bgpServer.Log().Error("failed to delete peer",
				slog.String("Topic", "config"),
				slog.String("Key", p.State.NeighborAddress.String()),
				slog.Any("Error", err),
			)
		}
	}
}

func updateNeighbors(ctx context.Context, bgpServer *server.BgpServer, updated []oc.Neighbor) bool {
	needsSoftResetIn := false
	for _, p := range updated {
		bgpServer.Log().Info("update peer",
			slog.String("Topic", "config"), slog.String("Key", p.State.NeighborAddress.String()))
		u, err := bgpServer.UpdatePeer(ctx, &api.UpdatePeerRequest{
			Peer: oc.NewPeerFromConfigStruct(&p),
		})
		if err != nil {
			bgpServer.Log().Error("failed to update peer",
				slog.String("Topic", "config"),
				slog.String("Key", p.State.NeighborAddress.String()),
				slog.Any("Error", err),
			)
			continue
		}
		needsSoftResetIn = needsSoftResetIn || u.NeedsSoftResetIn
	}

	return needsSoftResetIn
}

// InitialConfig applies initial configuration to a pristine gobgp instance. It
// can only be called once for an instance. Subsequent changes to the
// configuration can be applied using UpdateConfig. The BgpConfigSet can be
// obtained by calling ReadConfigFile. If graceful restart behavior is desired,
// pass true for isGracefulRestart. Otherwise, pass false. Any error applying
// the initial configuration is returned.
func InitialConfig(ctx context.Context, bgpServer *server.BgpServer, newConfig *oc.BgpConfigSet, isGracefulRestart bool) (*oc.BgpConfigSet, error) {
	if err := bgpServer.StartBgp(ctx, &api.StartBgpRequest{
		Global: oc.NewGlobalFromConfigStruct(&newConfig.Global),
	}); err != nil {
		return nil, err
	}

	if newConfig.Zebra.Config.Enabled {
		tps := newConfig.Zebra.Config.RedistributeRouteTypeList
		l := make([]string, 0, len(tps))
		l = append(l, tps...)
		err := bgpServer.EnableZebra(ctx, &api.EnableZebraRequest{
			Url:                  newConfig.Zebra.Config.Url,
			RouteTypes:           l,
			Version:              uint32(newConfig.Zebra.Config.Version),
			NexthopTriggerEnable: newConfig.Zebra.Config.NexthopTriggerEnable,
			NexthopTriggerDelay:  uint32(newConfig.Zebra.Config.NexthopTriggerDelay),
			MplsLabelRangeSize:   newConfig.Zebra.Config.MplsLabelRangeSize,
			SoftwareName:         newConfig.Zebra.Config.SoftwareName,
		})
		if err != nil {
			// Do not abort startup here. zebra.NewClient dials the zserv
			// socket once and never retries, so this fails when zebra is
			// not listening yet, not when the config is wrong.
			bgpServer.Log().Error("failed to set zebra config",
				slog.String("Topic", "config"), slog.Any("Error", err))
		}
	}

	for _, c := range newConfig.RpkiServers {
		err := bgpServer.AddRpki(ctx, &api.AddRpkiRequest{
			Address:  c.Config.Address.String(),
			Port:     c.Config.Port,
			Lifetime: c.Config.RecordLifetime,
		})
		if err != nil {
			bgpServer.Log().Error("failed to set rpki config",
				slog.String("Topic", "config"), slog.Any("Error", err))
			return nil, fmt.Errorf("failed to set rpki config: %w", err)
		}
	}
	f := func(t oc.BmpRouteMonitoringPolicyType) api.AddBmpRequest_MonitoringPolicy {
		switch t {
		case oc.BMP_ROUTE_MONITORING_POLICY_TYPE_PRE_POLICY:
			return api.AddBmpRequest_MONITORING_POLICY_PRE
		case oc.BMP_ROUTE_MONITORING_POLICY_TYPE_POST_POLICY:
			return api.AddBmpRequest_MONITORING_POLICY_POST
		case oc.BMP_ROUTE_MONITORING_POLICY_TYPE_BOTH:
			return api.AddBmpRequest_MONITORING_POLICY_BOTH
		case oc.BMP_ROUTE_MONITORING_POLICY_TYPE_LOCAL_RIB:
			return api.AddBmpRequest_MONITORING_POLICY_LOCAL
		case oc.BMP_ROUTE_MONITORING_POLICY_TYPE_ALL:
			return api.AddBmpRequest_MONITORING_POLICY_ALL
		}
		return api.AddBmpRequest_MONITORING_POLICY_UNSPECIFIED
	}

	for _, c := range newConfig.BmpServers {
		err := bgpServer.AddBmp(ctx, &api.AddBmpRequest{
			Address:           c.Config.Address.String(),
			Port:              c.Config.Port,
			SysName:           c.Config.SysName,
			SysDescr:          c.Config.SysDescr,
			Policy:            f(c.Config.RouteMonitoringPolicy),
			StatisticsTimeout: int32(c.Config.StatisticsTimeout),
		})
		if err != nil {
			bgpServer.Log().Error("failed to set bmp config",
				slog.String("Topic", "config"), slog.Any("Error", err))
			return nil, fmt.Errorf("failed to set bmp config: %w", err)
		}
	}
	for _, vrf := range newConfig.Vrfs {
		rd, err := bgp.ParseRouteDistinguisher(vrf.Config.Rd)
		if err != nil {
			bgpServer.Log().Error("failed to load vrf rd config",
				slog.String("Topic", "config"), slog.Any("Error", err))
			return nil, fmt.Errorf("failed to load vrf rd config: %w", err)
		}

		importRtList, err := marshalRouteTargets(vrf.Config.ImportRtList)
		if err != nil {
			bgpServer.Log().Error("failed to load vrf import rt config",
				slog.String("Topic", "config"), slog.Any("Error", err))
			return nil, fmt.Errorf("failed to load vrf import rt config: %w", err)
		}
		exportRtList, err := marshalRouteTargets(vrf.Config.ExportRtList)
		if err != nil {
			bgpServer.Log().Error("failed to load vrf export rt config",
				slog.String("Topic", "config"), slog.Any("Error", err))
			return nil, fmt.Errorf("failed to load vrf export rt config: %w", err)
		}

		a, err := apiutil.MarshalRD(rd)
		if err != nil {
			bgpServer.Log().Error("failed to set vrf config",
				slog.String("Topic", "config"), slog.Any("Error", err))
			return nil, fmt.Errorf("failed to set vrf config: %w", err)
		}
		err = bgpServer.AddVrf(ctx, &api.AddVrfRequest{
			Vrf: &api.Vrf{
				Name:     vrf.Config.Name,
				Rd:       a,
				Id:       vrf.Config.Id,
				ImportRt: importRtList,
				ExportRt: exportRtList,
			},
		})
		if err != nil {
			bgpServer.Log().Error("failed to set vrf config",
				slog.String("Topic", "config"), slog.Any("Error", err))
			return nil, fmt.Errorf("failed to set vrf config: %w", err)
		}
	}
	for _, c := range newConfig.MrtDump {
		if len(c.Config.FileName) == 0 {
			continue
		}

		dump_type := api.EnableMrtRequest_DUMP_TYPE_UNSPECIFIED
		switch c.Config.DumpType {
		case oc.MRT_TYPE_UPDATES:
			dump_type = api.EnableMrtRequest_DUMP_TYPE_UPDATES
		case oc.MRT_TYPE_TABLE:
			dump_type = api.EnableMrtRequest_DUMP_TYPE_TABLE
		}

		err := bgpServer.EnableMrt(ctx, &api.EnableMrtRequest{
			DumpType:         dump_type,
			Filename:         c.Config.FileName,
			DumpInterval:     c.Config.DumpInterval,
			RotationInterval: c.Config.RotationInterval,
		})
		if err != nil {
			bgpServer.Log().Error("failed to set mrt config",
				slog.String("Topic", "config"), slog.Any("Error", err))
			return nil, fmt.Errorf("failed to set mrt config: %w", err)
		}
	}
	p := oc.ConfigSetToRoutingPolicy(newConfig)
	rp, err := table.NewAPIRoutingPolicyFromConfigStruct(p)
	if err != nil {
		bgpServer.Log().Error("failed to update policy config",
			slog.String("Topic", "config"), slog.Any("Error", err))
		return nil, fmt.Errorf("failed to update policy config: %w", err)
	}
	if err := bgpServer.SetPolicies(ctx, &api.SetPoliciesRequest{
		DefinedSets: rp.DefinedSets,
		Policies:    rp.Policies,
	}); err != nil {
		bgpServer.Log().Error("failed to set policies",
			slog.String("Topic", "config"), slog.Any("Error", err))
		return nil, fmt.Errorf("failed to set policies: %w", err)
	}

	if err := assignGlobalpolicy(ctx, bgpServer, &newConfig.Global.ApplyPolicy.Config, stopOnConfigError); err != nil {
		return nil, err
	}

	// keychains and new keys must exist before peers can reference them
	keychains, err := oc.NewTcpAoKeychainsFromConfigStruct(newConfig.Keychains)
	if err != nil {
		return nil, err
	}
	addTcpAoKeychains(ctx, bgpServer, keychains)

	added := newConfig.Neighbors
	addedPg := newConfig.PeerGroups
	if isGracefulRestart {
		for i, n := range added {
			if n.GracefulRestart.Config.Enabled {
				added[i].GracefulRestart.State.LocalRestarting = true
			}
		}
	}

	if err := addPeerGroups(ctx, bgpServer, addedPg, stopOnConfigError); err != nil {
		return nil, err
	}
	if err := addDynamicNeighbors(ctx, bgpServer, newConfig.DynamicNeighbors, stopOnConfigError); err != nil {
		return nil, err
	}
	if err := addNeighbors(ctx, bgpServer, added, stopOnConfigError); err != nil {
		return nil, err
	}
	return newConfig, nil
}

// UpdateConfig updates the configuration of a running gobgp instance.
// InitialConfig must have been called once before this can be called for
// subsequent changes to config. The differences are that this call 1) does not
// hangle graceful restart and 2) requires a BgpConfigSet for the previous
// configuration so that it can compute the delta between it and the new
// config. The new BgpConfigSet can be obtained using ReadConfigFile.
// Reload keeps the previous runtime behavior: config apply errors are logged,
// but they do not abort the running daemon or reject the whole reload.
func UpdateConfig(ctx context.Context, bgpServer *server.BgpServer, c, newConfig *oc.BgpConfigSet) (*oc.BgpConfigSet, error) {
	addedPg, deletedPg, updatedPg := oc.UpdatePeerGroupConfig(bgpServer.Log(), c, newConfig)
	added, deleted, updated := oc.UpdateNeighborConfig(bgpServer.Log(), c, newConfig)
	addedKeychains, deletedKeychains, upsertKeyUpdates, deleteKeyUpdates, err := tcpAoKeychainConfigChanges(c.Keychains, newConfig.Keychains)
	if err != nil {
		return c, err
	}
	updatePolicy := oc.CheckPolicyDifference(bgpServer.Log(), oc.ConfigSetToRoutingPolicy(c), oc.ConfigSetToRoutingPolicy(newConfig))

	if updatePolicy {
		bgpServer.Log().Info("policy config is updated", slog.String("Topic", "config"))
		p := oc.ConfigSetToRoutingPolicy(newConfig)
		rp, err := table.NewAPIRoutingPolicyFromConfigStruct(p)
		if err != nil {
			bgpServer.Log().Error("failed to update policy config",
				slog.String("Topic", "config"), slog.Any("Error", err))
		} else if err := bgpServer.SetPolicies(ctx, &api.SetPoliciesRequest{
			DefinedSets: rp.DefinedSets,
			Policies:    rp.Policies,
		}); err != nil {
			bgpServer.Log().Error("failed to set policies",
				slog.String("Topic", "config"), slog.Any("Error", err))
		}
	}
	// global policy update
	if !newConfig.Global.ApplyPolicy.Config.Equal(&c.Global.ApplyPolicy.Config) {
		_ = assignGlobalpolicy(ctx, bgpServer, &newConfig.Global.ApplyPolicy.Config, continueOnConfigError)
		updatePolicy = true
	}

	// keychains and new keys must exist before peers can reference them
	addTcpAoKeychains(ctx, bgpServer, addedKeychains)
	updateTcpAoKeychains(ctx, bgpServer, upsertKeyUpdates)

	// peer groups must exist before peers can reference them
	_ = addPeerGroups(ctx, bgpServer, addedPg, continueOnConfigError)
	needsSoftResetIn := updatePeerGroups(ctx, bgpServer, updatedPg)
	updatePolicy = updatePolicy || needsSoftResetIn

	_ = addDynamicNeighbors(ctx, bgpServer, newConfig.DynamicNeighbors, continueOnConfigError)
	_ = addNeighbors(ctx, bgpServer, added, continueOnConfigError)
	deleteNeighbors(ctx, bgpServer, deleted)
	needsSoftResetIn = updateNeighbors(ctx, bgpServer, updated)
	updatePolicy = updatePolicy || needsSoftResetIn

	// peer groups can only be removed after peers stop referencing them
	deletePeerGroups(ctx, bgpServer, deletedPg)

	// keys and keychains can only be removed after peers stop referencing them
	updateTcpAoKeychains(ctx, bgpServer, deleteKeyUpdates)
	deleteTcpAoKeychains(ctx, bgpServer, deletedKeychains)

	if updatePolicy {
		if err := bgpServer.ResetPeer(ctx, &api.ResetPeerRequest{
			Address:   "",
			Direction: api.ResetPeerRequest_DIRECTION_IN,
			Soft:      true,
		}); err != nil {
			bgpServer.Log().Error("failed to update policy config",
				slog.String("Topic", "config"), slog.Any("Error", err))
		}
	}
	return newConfig, nil
}

func addTcpAoKeychains(ctx context.Context, bgpServer *server.BgpServer, chains []*api.TcpAoKeychain) {
	for _, chain := range chains {
		if err := bgpServer.AddTcpAoKeychain(ctx, &api.AddTcpAoKeychainRequest{Keychain: chain}); err != nil {
			bgpServer.Log().Error("failed to add TCP-AO keychain",
				slog.String("Topic", "config"),
				slog.String("Key", chain.Name),
				slog.Any("Error", err),
			)
		}
	}
}

func updateTcpAoKeychains(ctx context.Context, bgpServer *server.BgpServer, updates []*api.UpdateTcpAoKeychainRequest) {
	for _, update := range updates {
		if _, err := bgpServer.UpdateTcpAoKeychain(ctx, update); err != nil {
			bgpServer.Log().Error("failed to update TCP-AO keychain",
				slog.String("Topic", "config"),
				slog.String("Key", update.Name),
				slog.Any("Error", err),
			)
		}
	}
}

func deleteTcpAoKeychains(ctx context.Context, bgpServer *server.BgpServer, chains []string) {
	for _, name := range chains {
		if err := bgpServer.DeleteTcpAoKeychain(ctx, &api.DeleteTcpAoKeychainRequest{Name: name}); err != nil {
			bgpServer.Log().Error("failed to delete TCP-AO keychain",
				slog.String("Topic", "config"),
				slog.String("Key", name),
				slog.Any("Error", err),
			)
		}
	}
}

func tcpAoKeychainConfigChanges(current, desired []oc.Keychain) (
	added []*api.TcpAoKeychain,
	deleted []string,
	upsertKeyUpdates []*api.UpdateTcpAoKeychainRequest,
	deleteKeyUpdates []*api.UpdateTcpAoKeychainRequest,
	err error,
) {
	currentChains, err := oc.NewTcpAoKeychainsFromConfigStruct(current)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	desiredChains, err := oc.NewTcpAoKeychainsFromConfigStruct(desired)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, desiredChain := range desiredChains {
		currentChain := findAPITcpAoKeychain(currentChains, desiredChain.Name)
		if currentChain == nil {
			added = append(added, desiredChain)
			continue
		}
		addKeys, deleteKeys := tcpAoKeyChanges(currentChain.Keys, desiredChain.Keys)
		if len(addKeys) == 0 && len(deleteKeys) == 0 {
			continue
		}
		update := &api.UpdateTcpAoKeychainRequest{
			Name:       desiredChain.Name,
			DeleteKeys: deleteKeys,
		}
		if len(addKeys) != 0 {
			update.AddKeys = addKeys
			upsertKeyUpdates = append(upsertKeyUpdates, update)
		} else {
			deleteKeyUpdates = append(deleteKeyUpdates, update)
		}
	}
	for _, currentChain := range currentChains {
		if findAPITcpAoKeychain(desiredChains, currentChain.Name) != nil {
			continue
		}
		deleted = append(deleted, currentChain.Name)
	}
	return added, deleted, upsertKeyUpdates, deleteKeyUpdates, nil
}

func findAPITcpAoKeychain(chains []*api.TcpAoKeychain, name string) *api.TcpAoKeychain {
	for _, chain := range chains {
		if chain.Name == name {
			return chain
		}
	}
	return nil
}

func tcpAoKeyChanges(current, desired []*api.TcpAoKey) (added, deleted []*api.TcpAoKey) {
	find := func(keys []*api.TcpAoKey, sendID, receiveID uint32) *api.TcpAoKey {
		for _, key := range keys {
			if key.SendId == sendID && key.ReceiveId == receiveID {
				return key
			}
		}
		return nil
	}
	for _, key := range current {
		desiredKey := find(desired, key.SendId, key.ReceiveId)
		if desiredKey == nil || !tcpAoKeysEqual(key, desiredKey) {
			deleted = append(deleted, &api.TcpAoKey{SendId: key.SendId, ReceiveId: key.ReceiveId})
		}
	}
	for _, key := range desired {
		currentKey := find(current, key.SendId, key.ReceiveId)
		if currentKey == nil || !tcpAoKeysEqual(key, currentKey) {
			added = append(added, key)
		}
	}
	return added, deleted
}

func tcpAoKeysEqual(a, b *api.TcpAoKey) bool {
	return a.SendId == b.SendId &&
		a.ReceiveId == b.ReceiveId &&
		a.Algorithm == b.Algorithm &&
		bytes.Equal(a.MasterKey, b.MasterKey) &&
		a.ExcludeTcpOptions == b.ExcludeTcpOptions
}
