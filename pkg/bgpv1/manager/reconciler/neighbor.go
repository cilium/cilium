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
		curNeigh []v2alpha1api.CiliumBGPNeighbor = nil
	)
	newNeigh := p.DesiredConfig.Neighbors
	l.Debugf("Begin reconciling peers for virtual router with local ASN %v", p.DesiredConfig.LocalASN)

	// sc.Config can be nil if there is no previous configuration.
	if p.CurrentServer.Config != nil {
		curNeigh = p.CurrentServer.Config.Neighbors
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
			key = fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)
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
	for i, n := range curNeigh {
		var (
			key = fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)
			h   *member
			ok  bool
		)
		if h, ok = nset[key]; !ok {
			nset[key] = &member{
				cur: &curNeigh[i],
			}
			continue
		}
		h.cur = &curNeigh[i]
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

	if len(toCreate) > 0 || len(toRemove) > 0 || len(toUpdate) > 0 {
		l.Infof("Reconciling peers for virtual router with local ASN %v", p.DesiredConfig.LocalASN)
	} else {
		l.Debugf("No peer changes necessary for virtual router with local ASN %v", p.DesiredConfig.LocalASN)
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
		r.updatePeerPassword(p.CurrentServer, n, tcpPassword)
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
		if r.changedPeerPassword(p.CurrentServer, n, tcpPassword) {
			r.updatePeerPassword(p.CurrentServer, n, tcpPassword)
		}
	}

	// remove neighbors
	for _, n := range toRemove {
		l.Infof("Removing peer %v %v from local ASN %v", n.PeerAddress, n.PeerASN, p.DesiredConfig.LocalASN)
		if err := p.CurrentServer.Server.RemoveNeighbor(ctx, types.NeighborRequest{Neighbor: n, VR: p.DesiredConfig}); err != nil {
			return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.PeerAddress, n.PeerASN, err)
		}
	}

	l.Infof("Done reconciling peers for virtual router with local ASN %v", p.DesiredConfig.LocalASN)
	return nil
}

// NeighborReconcilerMetadata keeps a map of peers to passwords, fetched from
// secrets. Key is PeerAddress+PeerASN.
type NeighborReconcilerMetadata map[string]string

func (r *NeighborReconciler) getMetadata(sc *instance.ServerWithConfig) NeighborReconcilerMetadata {
	if _, found := sc.ReconcilerMetadata[r.Name()]; !found {
		sc.ReconcilerMetadata[r.Name()] = make(NeighborReconcilerMetadata)
	}
	return sc.ReconcilerMetadata[r.Name()].(NeighborReconcilerMetadata)
}

func (r *NeighborReconciler) fetchPeerPassword(sc *instance.ServerWithConfig, n *v2alpha1api.CiliumBGPNeighbor) (string, error) {
	peerPasswords := r.getMetadata(sc)

	l := log.WithFields(
		logrus.Fields{
			"component": "NeighborReconciler.fetchPeerPassword",
		},
	)
	if n.AuthSecretRef != nil {
		secretRef := *n.AuthSecretRef
		old := peerPasswords[fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)]

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
	peerPasswords := r.getMetadata(sc)

	key := fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)
	old := peerPasswords[key]
	return old != tcpPassword
}

func (r *NeighborReconciler) updatePeerPassword(sc *instance.ServerWithConfig, n *v2alpha1api.CiliumBGPNeighbor, tcpPassword string) {
	peerPasswords := r.getMetadata(sc)

	key := fmt.Sprintf("%s%d", n.PeerAddress, n.PeerASN)
	peerPasswords[key] = tcpPassword
}
