// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"
)

// NeighborReconciler is a ConfigReconciler which reconciles the peers of the
// provided BGP server with the provided CiliumBGPVirtualRouter.
type NeighborReconciler struct {
	Logger       logrus.FieldLogger
	SecretStore  store.BGPCPResourceStore[*slim_corev1.Secret]
	PeerConfig   store.BGPCPResourceStore[*v2alpha1.CiliumBGPPeerConfig]
	DaemonConfig *option.DaemonConfig
}

type NeighborReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler-v2"`
}

type NeighborReconcilerIn struct {
	cell.In
	Logger       logrus.FieldLogger
	SecretStore  store.BGPCPResourceStore[*slim_corev1.Secret]
	PeerConfig   store.BGPCPResourceStore[*v2alpha1.CiliumBGPPeerConfig]
	DaemonConfig *option.DaemonConfig
}

func NewNeighborReconciler(params NeighborReconcilerIn) NeighborReconcilerOut {
	logger := params.Logger.WithField(types.ReconcilerLogField, "Neighbor")

	return NeighborReconcilerOut{
		Reconciler: &NeighborReconciler{
			Logger:       logger,
			SecretStore:  params.SecretStore,
			PeerConfig:   params.PeerConfig,
			DaemonConfig: params.DaemonConfig,
		},
	}
}

// PeerData keeps a peer and its configuration. It also keeps the TCP password from secret store.
// +deepequal-gen=true
// Note:  If you change PeerDate, do not forget to 'make generate-k8s-api', which will update DeepEqual method.
type PeerData struct {
	Peer     *v2alpha1.CiliumBGPNodePeer
	Config   *v2alpha1.CiliumBGPPeerConfigSpec
	Password string
}

// NeighborReconcilerMetadata keeps a map of running peers to peer configuration.
// key is the peer name.
type NeighborReconcilerMetadata map[string][]*PeerData

func (r *NeighborReconciler) getMetadata(i *instance.BGPInstance) NeighborReconcilerMetadata {
	if _, found := i.Metadata[r.Name()]; !found {
		i.Metadata[r.Name()] = make(NeighborReconcilerMetadata)
	}
	return i.Metadata[r.Name()].(NeighborReconcilerMetadata)
}

func (r *NeighborReconciler) upsertMetadata(i *instance.BGPInstance, instanceName string, d *PeerData) {
	if i == nil || d == nil {
		return
	}

	neighMetadata := r.getMetadata(i)

	peers, exists := neighMetadata[instanceName]
	if !exists {
		neighMetadata[instanceName] = []*PeerData{d}
		return
	}

	found := false
	for i, p := range peers {
		if p.Peer.Name == d.Peer.Name {
			peers[i] = d
			found = true
			break
		}
	}

	if !found {
		peers = append(peers, d)
	}

	neighMetadata[instanceName] = peers
}

func (r *NeighborReconciler) deleteMetadata(i *instance.BGPInstance, instanceName string, d *PeerData) {
	if i == nil || d == nil {
		return
	}

	neighMetadata := r.getMetadata(i)
	peers, exists := neighMetadata[instanceName]
	if !exists {
		return
	}

	for i, p := range peers {
		if p.Peer.Name == d.Peer.Name {
			peers[i] = peers[len(peers)-1]
			peers = peers[:len(peers)-1]
			break
		}
	}

	neighMetadata[instanceName] = peers
}

func (r *NeighborReconciler) Name() string {
	return "Neighbor"
}

// Priority of neighbor reconciler is higher than pod/service announcements.
// This is important for graceful restart case, where all expected routes are pushed
// into gobgp RIB before neighbors are added. So, gobgp can send out all prefixes
// within initial update message exchange with neighbors before sending EOR marker.
func (r *NeighborReconciler) Priority() int {
	return 60
}

func (r *NeighborReconciler) Reconcile(ctx context.Context, p ReconcileParams) error {
	if p.DesiredConfig == nil {
		return fmt.Errorf("attempted neighbor reconciliation with nil CiliumBGPNodeInstance")
	}
	if p.BGPInstance == nil {
		return fmt.Errorf("attempted neighbor reconciliation with nil BGPInstance")
	}

	var (
		l = r.Logger.WithFields(logrus.Fields{
			types.InstanceLogField: p.DesiredConfig.Name,
		})

		toCreate []*PeerData
		toRemove []*PeerData
		toUpdate []*PeerData
		curNeigh []*PeerData = nil
	)
	newNeigh := p.DesiredConfig.Peers

	l.Debug("Begin reconciling peers")

	// get current configured peers
	curInstance := r.getMetadata(p.BGPInstance)
	if curInstance != nil {
		curNeigh = curInstance[p.DesiredConfig.Name]
	}

	type member struct {
		new *PeerData
		cur *PeerData
	}

	nset := map[string]*member{}

	for i, n := range newNeigh {
		var (
			key = n.Name
			h   *member
			ok  bool
		)

		config, err := r.getPeerConfig(n.PeerConfigRef.Name)
		if err != nil {
			return err
		}

		passwd, err := r.getPeerPassword(p.DesiredConfig.Name, n.Name, config)
		if err != nil {
			return err
		}

		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				new: &PeerData{
					Peer:     &newNeigh[i],
					Config:   config,
					Password: passwd,
				},
			}
			continue
		}
		h.new = &PeerData{
			Peer:     &newNeigh[i],
			Config:   config,
			Password: passwd,
		}
	}

	for i, n := range curNeigh {
		var (
			key = n.Peer.Name
			h   *member
			ok  bool
		)

		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				cur: curNeigh[i],
			}
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

	// create new neighbors
	for _, n := range toCreate {
		l.WithField(types.PeerLogField, n.Peer.Name).Info("Adding peer")

		if err := p.BGPInstance.Router.AddNeighbor(ctx, types.NeighborRequest{
			Peer:       n.Peer,
			PeerConfig: n.Config,
			Password:   n.Password,
		}); err != nil {
			return fmt.Errorf("failed to add neigbhor %s in instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.upsertMetadata(p.BGPInstance, p.DesiredConfig.Name, n)
	}

	// update neighbors
	for _, n := range toUpdate {
		l.WithField(types.PeerLogField, n.Peer.Name).Info("Updating peer")

		if err := p.BGPInstance.Router.UpdateNeighbor(ctx, types.NeighborRequest{
			Peer:       n.Peer,
			PeerConfig: n.Config,
			Password:   n.Password,
		}); err != nil {
			return fmt.Errorf("failed to update neigbhor %s in instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.upsertMetadata(p.BGPInstance, p.DesiredConfig.Name, n)
	}

	// remove neighbors
	for _, n := range toRemove {
		l.WithField(types.PeerLogField, n.Peer.Name).Info("Removing peer")

		if err := p.BGPInstance.Router.RemoveNeighbor(ctx, types.NeighborRequest{
			Peer: n.Peer,
		}); err != nil {
			return fmt.Errorf("failed to remove neigbhor %s from instance %s: %w", n.Peer.Name, p.DesiredConfig.Name, err)
		}
		// update metadata
		r.deleteMetadata(p.BGPInstance, p.DesiredConfig.Name, n)
	}

	l.Debug("Done reconciling peers")
	return nil
}

// getPeerConfig returns the CiliumBGPPeerConfigSpec for the given peerConfigName. If config does not exist, nil is returned.
func (r *NeighborReconciler) getPeerConfig(peerConfigName string) (*v2alpha1.CiliumBGPPeerConfigSpec, error) {
	config, exists, err := r.PeerConfig.GetByKey(resource.Key{Name: peerConfigName})
	if err != nil {
		return nil, err
	}

	var conf *v2alpha1.CiliumBGPPeerConfigSpec
	if !exists {
		// if config does not exist, return default config
		conf = &v2alpha1.CiliumBGPPeerConfigSpec{}
	} else {
		conf = &config.Spec
	}

	conf.SetDefaults()

	return conf, nil
}

func (r *NeighborReconciler) getPeerPassword(instanceName, peerName string, config *v2alpha1.CiliumBGPPeerConfigSpec) (string, error) {
	if config == nil {
		return "", nil
	}

	l := r.Logger.WithFields(logrus.Fields{
		types.InstanceLogField: instanceName,
		types.PeerLogField:     peerName,
	})

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
		l.Debugf("Using TCP password from secret %q", secretRef)
		return tcpPassword, nil
	}
	return "", nil
}

func (r *NeighborReconciler) fetchSecret(name string) (map[string][]byte, bool, error) {
	if r.SecretStore == nil {
		return nil, false, fmt.Errorf("SecretsNamespace not configured")
	}
	item, ok, err := r.SecretStore.GetByKey(resource.Key{Namespace: r.DaemonConfig.BGPSecretsNamespace, Name: name})
	if err != nil || !ok {
		return nil, ok, err
	}
	result := map[string][]byte{}
	for k, v := range item.Data {
		result[k] = []byte(v)
	}
	return result, true, nil
}
