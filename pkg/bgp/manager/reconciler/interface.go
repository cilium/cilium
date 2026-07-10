// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	bgpTables "github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/slices"
)

var (
	linkOperStateUp      = netlink.LinkOperState(netlink.OperUp).String()
	linkOperStateUnknown = netlink.LinkOperState(netlink.OperUnknown).String()
)

type InterfaceReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type InterfaceReconcilerIn struct {
	cell.In

	Logger     *slog.Logger
	PeerAdvert *CiliumPeerAdvertisement

	DB                      *statedb.DB
	DeviceTable             statedb.Table[*tables.Device]
	DesiredRoutePolicyTable statedb.RWTable[*bgpTables.DesiredRoutePolicy]
}

type InterfaceReconciler struct {
	logger                  *slog.Logger
	peerAdvert              *CiliumPeerAdvertisement
	db                      *statedb.DB
	deviceTable             statedb.Table[*tables.Device]
	desiredRoutePolicyTable statedb.RWTable[*bgpTables.DesiredRoutePolicy]
	metadata                map[string]InterfaceReconcilerMetadata
}

type InterfaceReconcilerMetadata struct {
	AFPaths AFPathsMap
}

func NewInterfaceReconciler(params InterfaceReconcilerIn) InterfaceReconcilerOut {
	return InterfaceReconcilerOut{
		Reconciler: &InterfaceReconciler{
			logger:                  params.Logger.With(types.ReconcilerLogField, InterfaceReconcilerName),
			peerAdvert:              params.PeerAdvert,
			db:                      params.DB,
			deviceTable:             params.DeviceTable,
			desiredRoutePolicyTable: params.DesiredRoutePolicyTable,
			metadata:                make(map[string]InterfaceReconcilerMetadata),
		},
	}
	// NOTE: there is no need to trigger reconciliation upon Device table changes,
	// this is already done by the DefaultGatewayReconciler.
}

func (r *InterfaceReconciler) Name() string {
	return InterfaceReconcilerName
}

func (r *InterfaceReconciler) Priority() int {
	return InterfaceReconcilerPriority
}

func (r *InterfaceReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = InterfaceReconcilerMetadata{
		AFPaths: make(AFPathsMap),
	}
	return nil
}

func (r *InterfaceReconciler) Cleanup(i *instance.BGPInstance) {
	if i != nil {
		if err := cleanupDesiredRoutePolicyStatements(r.db, r.desiredRoutePolicyTable, i.Name, r.Name()); err != nil {
			r.logger.Warn("Failed to clean up desired route policies",
				logfields.Error, err,
				types.InstanceLogField, i.Name,
				logfields.Owner, r.Name(),
			)
		}
		delete(r.metadata, i.Name)
	}
}

func (r *InterfaceReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if err := p.ValidateParams(); err != nil {
		return err
	}

	desiredPeerAdverts, err := r.peerAdvert.GetConfiguredAdvertisements(p.DesiredConfig, v2.BGPInterfaceAdvert)
	if err != nil {
		return err
	}

	txn := r.db.ReadTxn()
	err = r.reconcileRoutePolicies(ctx, p, desiredPeerAdverts, txn)
	if err != nil {
		return err
	}

	return r.reconcilePaths(ctx, p, desiredPeerAdverts, txn)
}

func (r *InterfaceReconciler) getDesiredPaths(desiredPeerAdverts PeerAdvertisements, txn statedb.ReadTxn) (AFPathsMap, error) {
	desiredAdverts := make(AFPathsMap)
	for _, peerFamilyAdverts := range desiredPeerAdverts {
		for family, familyAdverts := range peerFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)
			pathsPerFamily, exists := desiredAdverts[agentFamily]
			if !exists {
				pathsPerFamily = make(PathMap)
				desiredAdverts[agentFamily] = pathsPerFamily
			}
			for _, advert := range familyAdverts {
				for _, prefix := range r.getInterfacePrefixes(advert, agentFamily, txn) {
					path, err := types.NewPathForPrefix(prefix)
					if err != nil {
						return nil, fmt.Errorf("failed to create path for prefix %s: %w", prefix, err)
					}
					path.Family = agentFamily
					pathsPerFamily[path.NLRI.String()] = path
				}
			}
		}
	}
	return desiredAdverts, nil
}

func (r *InterfaceReconciler) getDesiredRoutePolicyStatements(instanceName string, desiredPeerAdverts PeerAdvertisements, txn statedb.ReadTxn) ([]*bgpTables.DesiredRoutePolicy, error) {
	desiredStatements := []*bgpTables.DesiredRoutePolicy{}
	for peer, peerFamilyAdverts := range desiredPeerAdverts {
		if peer.Address == "" {
			continue
		}
		peerAddr, err := netip.ParseAddr(peer.Address)
		if err != nil {
			return nil, fmt.Errorf("failed to parse peer address: %w", err)
		}
		for family, familyAdverts := range peerFamilyAdverts {
			agentFamily := types.ToAgentFamily(family)
			for _, advert := range familyAdverts {
				var v4Prefixes, v6Prefixes types.PolicyPrefixList
				for _, prefix := range r.getInterfacePrefixes(advert, agentFamily, txn) {
					rpPrefix := types.RoutePolicyPrefix{CIDR: prefix, PrefixLenMin: prefix.Bits(), PrefixLenMax: prefix.Bits()}
					if agentFamily.Afi == types.AfiIPv4 {
						v4Prefixes = append(v4Prefixes, rpPrefix)
					}
					if agentFamily.Afi == types.AfiIPv6 {
						v6Prefixes = append(v6Prefixes, rpPrefix)
					}
				}
				if len(v6Prefixes) > 0 || len(v4Prefixes) > 0 {
					name := PolicyStatementName(advert.AdvertisementType, "")
					statements, err := CreatePolicyStatements(name, peerAddr, v4Prefixes, v6Prefixes, advert)
					if err != nil {
						return nil, err
					}
					for _, statement := range statements {
						desiredStatements = append(desiredStatements, &bgpTables.DesiredRoutePolicy{
							Instance:   instanceName,
							Peer:       peer.Name,
							PolicyType: types.RoutePolicyTypeExport,
							Priority:   r.Priority(),
							Owner:      r.Name(),
							Statement:  statement,
						})
					}
				}
			}
		}
	}
	return desiredStatements, nil
}

func (r *InterfaceReconciler) getInterfacePrefixes(advert v2.BGPAdvertisement, family types.Family, txn statedb.ReadTxn) []netip.Prefix {
	var prefixes []netip.Prefix
	if advert.Interface == nil {
		return nil
	}
	dev, _, found := r.deviceTable.Get(txn, tables.DeviceByName(advert.Interface.Name))
	if !found {
		return nil
	}
	// Skip devices which are not:
	// - administratively up,
	// - operationally up or unknown (loopbacks and dummy interfaces are always unknown).
	if dev.Flags&net.FlagUp == 0 ||
		(dev.OperStatus != linkOperStateUp && dev.OperStatus != linkOperStateUnknown) {
		return nil
	}
	for _, addr := range dev.Addrs {
		// Skip non-matching address families.
		if family.Afi == types.AfiIPv4 && !addr.Addr.Is4() ||
			family.Afi == types.AfiIPv6 && !addr.Addr.Is6() {
			continue
		}
		// Skip:
		// - IPv4-mapped IPv6 addresses,
		// - unspecified, loopback, multicast and link-local IPv6 addresses,
		// - unspecified, loopback and multicast IPv4 addresses (link-local IPv4 is allowed).
		if addr.Addr.Is4In6() ||
			(addr.Addr.Is6() && !addr.Addr.IsGlobalUnicast()) ||
			(addr.Addr.Is4() && !(addr.Addr.IsGlobalUnicast() || addr.Addr.IsLinkLocalUnicast())) {
			continue
		}
		prefixes = append(prefixes, netip.PrefixFrom(addr.Addr, addr.Addr.BitLen()))
	}
	return slices.Unique(prefixes) // avoid duplicates in case that the same IP is applied with a different mask
}

func (r *InterfaceReconciler) reconcilePaths(ctx context.Context, p ReconcileParams, desiredPeerAdverts PeerAdvertisements, txn statedb.ReadTxn) error {
	metadata := r.getMetadata(p.BGPInstance)

	// get desired paths per address family
	desiredFamilyAdverts, err := r.getDesiredPaths(desiredPeerAdverts, txn)
	if err != nil {
		return err
	}

	// reconcile family advertisements
	updatedAFPaths, err := ReconcileAFPaths(&ReconcileAFPathsParams{
		Logger:       r.logger.With(types.InstanceLogField, p.DesiredConfig.Name),
		Ctx:          ctx,
		Router:       p.BGPInstance.Router,
		DesiredPaths: desiredFamilyAdverts,
		CurrentPaths: metadata.AFPaths,
	})

	metadata.AFPaths = updatedAFPaths
	r.setMetadata(p.BGPInstance, metadata)
	return err
}

func (r *InterfaceReconciler) reconcileRoutePolicies(_ context.Context, p ReconcileParams, desiredPeerAdverts PeerAdvertisements, txn statedb.ReadTxn) error {
	desiredStatements, err := r.getDesiredRoutePolicyStatements(p.BGPInstance.Name, desiredPeerAdverts, txn)
	if err != nil {
		return err
	}
	tx := r.db.WriteTxn(r.desiredRoutePolicyTable)
	defer tx.Abort()

	if err := reconcileDesiredRoutePolicyStatements(tx, r.desiredRoutePolicyTable, p.BGPInstance.Name, r.Name(), resource.Key{}, desiredStatements); err != nil {
		return err
	}
	tx.Commit()
	return nil
}

func (r *InterfaceReconciler) getMetadata(i *instance.BGPInstance) InterfaceReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *InterfaceReconciler) setMetadata(i *instance.BGPInstance, metadata InterfaceReconcilerMetadata) {
	r.metadata[i.Name] = metadata
}
