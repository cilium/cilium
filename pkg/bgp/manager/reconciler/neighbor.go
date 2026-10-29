// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/pkg/bgp/config"
	"github.com/cilium/cilium/pkg/bgp/manager/instance"
	"github.com/cilium/cilium/pkg/bgp/manager/store"
	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// errTCPAOSecretInvalid is returned by getPeerTCPAO when the TCP-AO Secret referenced by a peer
// exists, but its content does not yield a valid keychain for the peer configuration (e.g. a
// master key entry is missing or a master key is too long).
var errTCPAOSecretInvalid = errors.New("invalid TCP-AO secret")

// NeighborReconciler is a ConfigReconciler which reconciles the peers of the
// provided BGP server with the provided CiliumBGPVirtualRouter.
type NeighborReconciler struct {
	logger      *slog.Logger
	SecretStore store.BGPCPResourceStore[*slim_corev1.Secret]
	PeerConfig  store.BGPCPResourceStore[*v2.CiliumBGPPeerConfig]
	DB          *statedb.DB
	DeviceTable statedb.Table[*tables.Device]
	BGPConfig   config.BGPConfig
	metadata    map[string]NeighborReconcilerMetadata
}

type NeighborReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

type NeighborReconcilerIn struct {
	cell.In
	Logger      *slog.Logger
	SecretStore store.BGPCPResourceStore[*slim_corev1.Secret]
	PeerConfig  store.BGPCPResourceStore[*v2.CiliumBGPPeerConfig]
	DB          *statedb.DB
	DeviceTable statedb.Table[*tables.Device]
	BGPConfig   config.BGPConfig
}

func NewNeighborReconciler(params NeighborReconcilerIn) NeighborReconcilerOut {
	logger := params.Logger.With(types.ReconcilerLogField, "Neighbor")

	return NeighborReconcilerOut{
		Reconciler: &NeighborReconciler{
			logger:      logger,
			SecretStore: params.SecretStore,
			PeerConfig:  params.PeerConfig,
			BGPConfig:   params.BGPConfig,
			DB:          params.DB,
			DeviceTable: params.DeviceTable,
			metadata:    make(map[string]NeighborReconcilerMetadata),
		},
	}
	// NOTE: there is no need to trigger reconciliation upon Device table changes,
	// this is already done by the DefaultGatewayReconciler.
}

// PeerData keeps a peer and its configuration. It also keeps the TCP password / TCP-AO keys from secret store.
// +deepequal-gen=true
// Note:  If you change PeerDate, do not forget to 'make generate-k8s-api', which will update DeepEqual method.
type PeerData struct {
	Peer     *v2.CiliumBGPNodePeer
	Config   *v2.CiliumBGPPeerConfigSpec
	Password string
	// TCPAO holds the TCP-AO configuration of the peer with the master keys resolved
	// from the referenced secret. nil if TCP-AO is not configured for the peer.
	TCPAO *types.NeighborTCPAO
}

// NeighborReconcilerMetadata keeps a map of running peers to peer configuration.
// Key is the peer name.
type NeighborReconcilerMetadata map[string]*PeerData

func (r *NeighborReconciler) getMetadata(i *instance.BGPInstance) NeighborReconcilerMetadata {
	return r.metadata[i.Name]
}

func (r *NeighborReconciler) upsertMetadata(i *instance.BGPInstance, d *PeerData) {
	if i == nil || d == nil {
		return
	}
	r.metadata[i.Name][d.Peer.Name] = d
}

func (r *NeighborReconciler) deleteMetadata(i *instance.BGPInstance, d *PeerData) {
	if i == nil || d == nil {
		return
	}
	delete(r.metadata[i.Name], d.Peer.Name)
}

func (r *NeighborReconciler) Name() string {
	return NeighborReconcilerName
}

// Priority of neighbor reconciler is higher than pod/service announcements.
// This is important for graceful restart case, where all expected routes are pushed
// into gobgp RIB before neighbors are added. So, gobgp can send out all prefixes
// within initial update message exchange with neighbors before sending EOR marker.
func (r *NeighborReconciler) Priority() int {
	return NeighborReconcilerPriority
}

func (r *NeighborReconciler) Init(i *instance.BGPInstance) error {
	if i == nil {
		return fmt.Errorf("BUG: %s reconciler initialization with nil BGPInstance", r.Name())
	}
	r.metadata[i.Name] = make(NeighborReconcilerMetadata)
	return nil
}

func (r *NeighborReconciler) Cleanup(i *instance.BGPInstance) {
	if i != nil {
		delete(r.metadata, i.Name)
	}
}

func (r *NeighborReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if err := p.ValidateParams(); err != nil {
		return err
	}

	var (
		l = r.logger.With(types.InstanceLogField, p.DesiredConfig.Name)

		toCreate []*PeerData
		toRemove []*PeerData
		toUpdate []*PeerData
	)
	curNeigh := r.getMetadata(p.BGPInstance)
	newNeigh := p.DesiredConfig.Peers

	l.Debug("Begin reconciling peers")

	type member struct {
		new *PeerData
		cur *PeerData
	}

	nset := map[string]*member{}

	// keepCurrent holds the IDs of the peers whose desired configuration can not be applied at
	// the moment and which must therefore be left as they currently are (neither updated nor
	// removed) by this reconciliation.
	keepCurrent := map[string]struct{}{}

	for i, n := range newNeigh {
		l := l.With(types.PeerLogField, n.Name)
		// validate that peer has ASN and address. In current implementation these fields are
		// mandatory for a peer. Eventually we will relax this restriction with implementation
		// of BGP unnumbered.
		if n.PeerASN == nil {
			return fmt.Errorf("peer %s does not have a PeerASN", n.Name)
		}

		if n.PeerAddress == nil {
			l.Debug("Peer does not have PeerAddress configured, skipping")
			continue
		}

		var (
			peer = &newNeigh[i]
			key  = r.neighborID(peer)
			h    *member
			ok   bool
		)

		config, exists, err := r.getPeerConfig(n.PeerConfigRef)
		if err != nil {
			return err
		}
		if !exists {
			continue // configured peer config does not exist, skip
		}

		passwd, err := r.getPeerPassword(p.DesiredConfig.Name, n.Name, config)
		if err != nil {
			return err
		}

		tcpAO, tcpAOReady, err := r.getPeerTCPAO(p.DesiredConfig.Name, n.Name, config)
		if err != nil {
			if !errors.Is(err, errTCPAOSecretInvalid) {
				return err
			}
			// The Secret exists but does not (yet) match the peer configuration. This is commonly
			// a transient state, e.g. while the Secret and the CiliumBGPPeerConfig of a key rotation
			// are being updated one after the other. Do not abort the reconciliation of the whole
			// instance (which would also block the unrelated peers of the instance), and do not
			// reset the session of the peer either if it already exists: leave the peer as it is
			// until the Secret and the configuration are consistent again. A peer which does not
			// exist yet is not created (fail closed).
			l.Warn("Peer has an invalid TCP-AO configuration, leaving the peer unchanged", logfields.Error, err)
			keepCurrent[key] = struct{}{}
			continue
		}
		if !tcpAOReady {
			// Unlike for the TCP MD5 password, do not fall back to an unauthenticated session
			// when the TCP-AO secret is not (yet) available.
			l.Warn("Peer has TCP-AO configured but the referenced secret is not available, skipping")
			continue
		}

		// If the local address is not provided via override and the source interface is provided in the peer config,
		// use the local address from the provided source interface.
		if ptr.Deref(peer.LocalAddress, "") == "" &&
			config.Transport != nil && ptr.Deref(config.Transport.SourceInterface, "") != "" {
			localAddr, found, err := r.getInterfaceLocalAddress(*config.Transport.SourceInterface, *n.PeerAddress)
			if err != nil {
				return err
			}
			if !found {
				l.Warn("Peer does not have a valid IP address on the configured source interface, skipping")
				continue
			}
			peer = peer.DeepCopy()
			peer.LocalAddress = &localAddr
		}

		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				new: &PeerData{
					Peer:     peer,
					Config:   config,
					Password: passwd,
					TCPAO:    tcpAO,
				},
			}
			continue
		}
		h.new = &PeerData{
			Peer:     peer,
			Config:   config,
			Password: passwd,
			TCPAO:    tcpAO,
		}
	}

	for i, n := range curNeigh {
		var (
			key = r.neighborID(n.Peer)
			h   *member
			ok  bool
		)

		if h, ok = nset[key]; !ok {
			h = &member{
				cur: curNeigh[i],
			}
			if _, keep := keepCurrent[key]; keep {
				// The desired configuration of the peer can not be applied at the moment, keep
				// the peer as it currently is.
				h.new = curNeigh[i]
			}
			nset[key] = h
			continue
		}
		h.cur = curNeigh[i]
	}

	for _, m := range nset {
		// present in new neighbors (set new) but not in current neighbors (set cur)
		if m.new != nil && m.cur == nil {
			toCreate = append(toCreate, m.new)
		}
		// present in current neighbors (set cur) but not in new neighbors (set new)
		if m.cur != nil && m.new == nil {
			toRemove = append(toRemove, m.cur)
		}
		// present in both new neighbors (set new) and current neighbors (set cur), update if they are not equal
		if m.cur != nil && m.new != nil {
			if !m.cur.DeepEqual(m.new) {
				toUpdate = append(toUpdate, m.new)
			}
		}
	}

	if len(toCreate) > 0 || len(toRemove) > 0 || len(toUpdate) > 0 {
		l.Info("Reconciling peers for instance")
	} else {
		l.Debug("No peer changes necessary")
	}

	// remove neighbors
	for _, n := range toRemove {
		l.Info("Removing peer", types.PeerLogField, n.Peer.Name)

		if err := p.BGPInstance.Router.RemoveNeighbor(ctx, types.ToNeighborV2(n.Peer, n.Config, "", nil)); err != nil {
			return fmt.Errorf("failed to remove neigbhor %s from instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.deleteMetadata(p.BGPInstance, n)
	}

	// update neighbors
	for _, n := range toUpdate {
		l.Info("Updating peer", types.PeerLogField, n.Peer.Name)

		if err := p.BGPInstance.Router.UpdateNeighbor(ctx, types.ToNeighborV2(n.Peer, n.Config, n.Password, n.TCPAO)); err != nil {
			return fmt.Errorf("failed to update neigbhor %s in instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.upsertMetadata(p.BGPInstance, n)
	}

	// create new neighbors
	for _, n := range toCreate {
		l.Info("Adding peer", types.PeerLogField, n.Peer.Name)

		if err := p.BGPInstance.Router.AddNeighbor(ctx, types.ToNeighborV2(n.Peer, n.Config, n.Password, n.TCPAO)); err != nil {
			return fmt.Errorf("failed to add neigbhor %s in instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.upsertMetadata(p.BGPInstance, n)
	}

	l.Debug("Done reconciling peers")
	return nil
}

// getPeerConfig returns the CiliumBGPPeerConfigSpec for the given peerConfig.
// If peerConfig is not specified, returns the default config.
// If the referenced peerConfig does not exist, exists returns false.
func (r *NeighborReconciler) getPeerConfig(peerConfig *v2.PeerConfigReference) (conf *v2.CiliumBGPPeerConfigSpec, exists bool, err error) {
	if peerConfig == nil || peerConfig.Name == "" {
		// if peer config is not specified, return default config
		conf = &v2.CiliumBGPPeerConfigSpec{}
		conf.SetDefaults()
		return conf, true, nil
	}

	config, exists, err := r.PeerConfig.GetByKey(resource.Key{Name: peerConfig.Name})
	if err != nil || !exists {
		if errors.Is(err, store.ErrStoreUninitialized) {
			err = errors.Join(err, ErrAbortReconcile)
		}
		return nil, exists, err
	}

	conf = config.Spec.DeepCopy() // copy to not ever modify config in store in SetDefaults()
	conf.SetDefaults()
	return conf, true, nil
}

func (r *NeighborReconciler) getPeerPassword(instanceName, peerName string, config *v2.CiliumBGPPeerConfigSpec) (string, error) {
	if config == nil {
		return "", nil
	}

	if config.AuthSecretRef != nil {
		secretRef := *config.AuthSecretRef

		secret, ok, err := r.fetchSecret(secretRef)
		if err != nil {
			return "", fmt.Errorf("failed to fetch secret %q: %w", secretRef, err)
		}
		if !ok {
			return "", nil
		}
		tcpPassword := string(secret["password"])
		if tcpPassword == "" {
			return "", fmt.Errorf("failed to fetch secret %q: missing password key", secretRef)
		}
		r.logger.Debug(
			"Using TCP password from secret",
			types.SecretRefLogField, secretRef,
			types.InstanceLogField, instanceName,
			types.PeerLogField, peerName,
		)
		return tcpPassword, nil
	}
	return "", nil
}

// getPeerTCPAO resolves the TCP-AO configuration of the peer, with the master keys taken from the
// referenced secret. Returns ready=false if TCP-AO is configured but the referenced secret does not exist.
func (r *NeighborReconciler) getPeerTCPAO(instanceName, peerName string, config *v2.CiliumBGPPeerConfigSpec) (tcpAO *types.NeighborTCPAO, ready bool, err error) {
	if config == nil || config.TCPAO == nil {
		return nil, true, nil
	}

	secretRef := config.TCPAO.SecretRef
	secret, ok, err := r.fetchSecret(secretRef)
	if err != nil {
		return nil, false, fmt.Errorf("failed to fetch secret %q: %w", secretRef, err)
	}
	if !ok {
		return nil, false, nil
	}

	tcpAO, err = types.ToNeighborTCPAOV2(config.TCPAO, secret)
	if err != nil {
		return nil, false, fmt.Errorf("%w %q: %w", errTCPAOSecretInvalid, secretRef, err)
	}

	r.logger.Debug(
		"Using TCP-AO keys from secret",
		types.SecretRefLogField, secretRef,
		types.InstanceLogField, instanceName,
		types.PeerLogField, peerName,
	)
	return tcpAO, true, nil
}

func (r *NeighborReconciler) fetchSecret(name string) (map[string][]byte, bool, error) {
	if r.SecretStore == nil {
		return nil, false, fmt.Errorf("SecretsNamespace not configured")
	}
	item, ok, err := r.SecretStore.GetByKey(resource.Key{Namespace: r.BGPConfig.SecretsNamespace, Name: name})
	if err != nil || !ok {
		if errors.Is(err, store.ErrStoreUninitialized) {
			err = errors.Join(err, ErrAbortReconcile)
		}
		return nil, ok, err
	}
	result := map[string][]byte{}
	for k, v := range item.Data {
		result[k] = []byte(v)
	}
	return result, true, nil
}

func (r *NeighborReconciler) neighborID(n *v2.CiliumBGPNodePeer) string {
	return fmt.Sprintf("%s%s%d", n.Name, *n.PeerAddress, *n.PeerASN)
}

func (r *NeighborReconciler) getInterfaceLocalAddress(interfaceName, peerAddress string) (localAddr string, found bool, err error) {
	peerAddr, err := netip.ParseAddr(peerAddress)
	if err != nil {
		return "", false, fmt.Errorf("failed to parse peer address %q: %w", peerAddress, err)
	}
	log := r.logger.With(
		logfields.Interface, interfaceName,
		types.PeerLogField, peerAddress,
	)
	dev, _, deviceFound := r.DeviceTable.Get(r.DB.ReadTxn(), tables.DeviceByName(interfaceName))
	if !deviceFound {
		log.Warn("Interface not found, can not use it as the source interface for the peer.")
		return "", false, nil
	}
	for _, addr := range dev.Addrs {
		// Skip families non-matching with the peer.
		if peerAddr.Is4() != addr.Addr.Is4() {
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
		if localAddr != "" {
			log.Warn("Multiple IP addresses found on the interface, can not use it as the source interface for the peer.")
			return "", false, nil
		}
		localAddr = addr.Addr.String()
		found = true
	}
	if !found {
		log.Warn("No usable IP addresses found on the interface, can not use it as the source interface for the peer.")
	} else {
		log.Debug("Using local IP address from the source interface", logfields.IPAddr, localAddr)
	}
	return localAddr, found, nil
}
