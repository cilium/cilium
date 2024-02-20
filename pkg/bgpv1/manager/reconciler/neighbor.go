// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"
)

type NeighborReconcilerOut struct {
	cell.Out

	Reconciler ConfigReconciler `group:"bgp-config-reconciler"`
}

// NeighborReconciler is a ConfigReconciler which reconciles the peers of the
// provided BGP server with the provided CiliumBGPVirtualRouter.
type NeighborReconciler struct {
	SecretStore  store.BGPCPResourceStore[*slim_corev1.Secret]
	DaemonConfig *option.DaemonConfig
}

func NewNeighborReconciler(SecretStore store.BGPCPResourceStore[*slim_corev1.Secret], DaemonConfig *option.DaemonConfig) NeighborReconcilerOut {
	return NeighborReconcilerOut{
		Reconciler: &NeighborReconciler{
			SecretStore:  SecretStore,
			DaemonConfig: DaemonConfig,
		},
	}
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
		return fmt.Errorf("attempted neighbor reconciliation with nil CiliumBGPPeeringPolicy")
	}
	if p.CurrentServer == nil {
		return fmt.Errorf("attempted neighbor reconciliation with nil ServerWithConfig")
	}
	var (
		l = log.WithFields(
			logrus.Fields{
				"component": "NeighborReconciler",
			},
		)
		toCreate []*v2alpha1api.CiliumBGPNeighbor
		toRemove []*v2alpha1api.CiliumBGPNeighbor
		toUpdate []*v2alpha1api.CiliumBGPNeighbor
		curNeigh []*v2alpha1api.CiliumBGPNeighbor = nil
	)
	newNeigh := p.DesiredConfig.Neighbors

	metaMap := r.getMetadata(p.CurrentServer)
	if len(metaMap) > 0 {
		curNeigh = []*v2alpha1api.CiliumBGPNeighbor{}
		for _, meta := range metaMap {
			curNeigh = append(curNeigh, meta.currentConfig)
		}
	}

	// an nset member which book keeps which universe it exists in.
	type member struct {
		new *v2alpha1api.CiliumBGPNeighbor
		cur *v2alpha1api.CiliumBGPNeighbor
	}

	nset := map[string]*member{}

	// populate set from universe of new neighbors
	for i, n := range newNeigh {
		var (
			key = r.neighborID(&n)
			h   *member
			ok  bool
		)
		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				new: &newNeigh[i],
			}
			continue
		}
		h.new = &newNeigh[i]
	}

	// populate set from universe of current neighbors
	for _, n := range curNeigh {
		var (
			key = r.neighborID(n)
			h   *member
			ok  bool
		)
		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				cur: n,
			}
			continue
		}
		h.cur = n
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
			} else {
				// Fetch the secret to check if the TCP password changed.
				tcpPassword, err := r.fetchPeerPassword(p.CurrentServer, m.new)
				if err != nil {
					return err
				}
				if r.changedPeerPassword(p.CurrentServer, m.new, tcpPassword) {
					toUpdate = append(toUpdate, m.new)
				}
			}
		}
	}

	// create new neighbors
	for _, n := range toCreate {
		l.Infof("Adding peer %v %v to local ASN %v", n.PeerAddress, n.PeerASN, p.DesiredConfig.LocalASN)
		tcpPassword, err := r.fetchPeerPassword(p.CurrentServer, n)
		if err != nil {
			return fmt.Errorf("failed fetching password for neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
		if err := p.CurrentServer.Server.AddNeighbor(ctx, types.NeighborRequest{Neighbor: n, Password: tcpPassword, VR: p.DesiredConfig}); err != nil {
			return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
		r.updateMetadata(p.CurrentServer, n, tcpPassword)
	}

	// update neighbors
	for _, n := range toUpdate {
		l.Infof("Updating peer %v %v in local ASN %v", n.PeerAddress, n.PeerASN, p.DesiredConfig.LocalASN)
		tcpPassword, err := r.fetchPeerPassword(p.CurrentServer, n)
		if err != nil {
			return fmt.Errorf("failed fetching password for neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
		if err := p.CurrentServer.Server.UpdateNeighbor(ctx, types.NeighborRequest{Neighbor: n, Password: tcpPassword, VR: p.DesiredConfig}); err != nil {
			return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
		r.updateMetadata(p.CurrentServer, n, tcpPassword)
	}

	// remove neighbors
	for _, n := range toRemove {
		l.Infof("Removing peer %v %v from local ASN %v", n.PeerAddress, n.PeerASN, p.DesiredConfig.LocalASN)
		if err := p.CurrentServer.Server.RemoveNeighbor(ctx, types.NeighborRequest{Neighbor: n, VR: p.DesiredConfig}); err != nil {
			return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
		r.deleteMetadata(p.CurrentServer, n)
	}

	return nil
}

// NeighborReconcilerMetadata keeps a map of peers to passwords, fetched from
// secrets. Key is PeerAddress+PeerASN.
type NeighborReconcilerMetadata map[string]neighborReconcilerMetadata

type neighborReconcilerMetadata struct {
	currentPassword string
	currentConfig   *v2alpha1api.CiliumBGPNeighbor
}

func (r *NeighborReconciler) getMetadata(sc *instance.ServerWithConfig) NeighborReconcilerMetadata {
	if _, found := sc.ReconcilerMetadata[r.Name()]; !found {
		sc.ReconcilerMetadata[r.Name()] = make(NeighborReconcilerMetadata)
	}
	return sc.ReconcilerMetadata[r.Name()].(NeighborReconcilerMetadata)
}

func (r *NeighborReconciler) fetchPeerPassword(sc *instance.ServerWithConfig, n *v2alpha1api.CiliumBGPNeighbor) (string, error) {
	l := log.WithFields(
		logrus.Fields{
			"component": "NeighborReconciler.fetchPeerPassword",
		},
	)
	if n.AuthSecretRef != nil {
		secretRef := *n.AuthSecretRef
		old := r.getMetadata(sc)[r.neighborID(n)].currentPassword

		secret, ok, err := r.fetchSecret(secretRef)
		if err != nil {
			return "", fmt.Errorf("failed to fetch secret %q: %w", secretRef, err)
		}
		if !ok {
			if old != "" {
				l.Errorf("Failed to fetch secret %q: not found (will continue with old secret)", secretRef)
				return old, nil
			}
			l.Errorf("Failed to fetch secret %q: not found (will continue with empty password)", secretRef)
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

func (r *NeighborReconciler) changedPeerPassword(sc *instance.ServerWithConfig, n *v2alpha1api.CiliumBGPNeighbor, tcpPassword string) bool {
	return r.getMetadata(sc)[r.neighborID(n)].currentPassword != tcpPassword
}

func (r *NeighborReconciler) updateMetadata(sc *instance.ServerWithConfig, n *v2alpha1api.CiliumBGPNeighbor, tcpPassword string) {
	r.getMetadata(sc)[r.neighborID(n)] = neighborReconcilerMetadata{
		currentPassword: tcpPassword,
		currentConfig:   n.DeepCopy(),
	}
}

func (r *NeighborReconciler) deleteMetadata(sc *instance.ServerWithConfig, n *v2alpha1api.CiliumBGPNeighbor) {
	delete(r.getMetadata(sc), r.neighborID(n))
}

func (r *NeighborReconciler) neighborID(n *v2alpha1api.CiliumBGPNeighbor) string {
	return fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)
}
