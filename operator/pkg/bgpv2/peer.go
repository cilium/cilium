// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"
)

type peerConfigStatusReconciler struct {
	cs              k8s_client.Clientset
	secretNamespace string
	secretStore     resource.Store[*slim_core_v1.Secret]
	peerConfigStore resource.Store[*cilium_api_v2alpha1.CiliumBGPPeerConfig]
}

type peerConfigStatusReconcilerIn struct {
	cell.In

	Clientset    k8s_client.Clientset
	DaemonConfig *option.DaemonConfig
	JobGroup     job.Group

	SecretResource     resource.Resource[*slim_core_v1.Secret]
	PeerConfigResource resource.Resource[*cilium_api_v2alpha1.CiliumBGPPeerConfig]
}

func registerPeerConfigStatusReconciler(in peerConfigStatusReconcilerIn) {
	if !in.DaemonConfig.BGPControlPlaneEnabled() {
		return
	}

	u := &peerConfigStatusReconciler{
		cs:              in.Clientset,
		secretNamespace: in.DaemonConfig.BGPSecretsNamespace,
	}

	in.JobGroup.Add(job.OneShot(
		"peer-config-status-reconciler",
		func(ctx context.Context, health cell.Health) error {
			ss, err := in.SecretResource.Store(ctx)
			if err != nil {
				return err
			}
			u.secretStore = ss

			ps, err := in.PeerConfigResource.Store(ctx)
			if err != nil {
				return err
			}
			u.peerConfigStore = ps

			se := in.SecretResource.Events(ctx)
			pe := in.PeerConfigResource.Events(ctx)

			for {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case e, ok := <-se:
					if !ok {
						continue
					}
					if e.Kind == resource.Sync {
						e.Done(nil)
						continue
					}
					e.Done(u.handleSecret(ctx, e))
				case e, ok := <-pe:
					if !ok {
						continue
					}
					if e.Kind != resource.Upsert {
						e.Done(nil)
						continue
					}
					e.Done(u.reconcilePeerConfig(ctx, e.Object))
				}
			}
		},
	))
}

func (u *peerConfigStatusReconciler) reconcilePeerConfig(ctx context.Context, config *cilium_api_v2alpha1.CiliumBGPPeerConfig) error {
	updateStatus := false

	authSecretMissing := u.authSecretMissing(config)

	if changed := u.updateMissingAuthSecretCondition(config, authSecretMissing); changed {
		updateStatus = true
	}

	slices.SortStableFunc(config.Status.Conditions, func(a, b meta_v1.Condition) int {
		return strings.Compare(a.Type, b.Type)
	})

	if updateStatus {
		if _, err := u.cs.CiliumV2alpha1().CiliumBGPPeerConfigs().UpdateStatus(ctx, config, meta_v1.UpdateOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func (u *peerConfigStatusReconciler) authSecretMissing(c *cilium_api_v2alpha1.CiliumBGPPeerConfig) bool {
	if c.Spec.AuthSecretRef == nil {
		return false
	}
	if _, exists, _ := u.secretStore.GetByKey(resource.Key{Namespace: u.secretNamespace, Name: *c.Spec.AuthSecretRef}); !exists {
		return true
	}
	return false
}

func (u *peerConfigStatusReconciler) updateMissingAuthSecretCondition(config *cilium_api_v2alpha1.CiliumBGPPeerConfig, missing bool) bool {
	cond := meta_v1.Condition{
		Type:               cilium_api_v2alpha1.BGPPeerConfigConditionMissingAuthSecret,
		Status:             meta_v1.ConditionFalse,
		ObservedGeneration: config.Generation,
		LastTransitionTime: meta_v1.Now(),
		Reason:             "MissingAuthSecret",
	}
	if missing {
		cond.Status = meta_v1.ConditionTrue
		cond.Message = fmt.Sprintf("Referenced Auth Secret %q is missing", *config.Spec.AuthSecretRef)
	}
	return meta.SetStatusCondition(&config.Status.Conditions, cond)
}

func (u *peerConfigStatusReconciler) handleSecret(ctx context.Context, e resource.Event[*slim_core_v1.Secret]) error {
	// Reconcile all peer configs that reference this secret. This is a bit
	// inefficient but since we don't expect a large number of PeerConfigs
	// or Secret in the BGP Secret namespace, this is acceptable.
	for _, pc := range u.peerConfigStore.List() {
		if pc.Spec.AuthSecretRef == nil {
			continue
		}
		if *pc.Spec.AuthSecretRef != e.Key.Name {
			continue
		}
		if err := u.reconcilePeerConfig(ctx, pc); err != nil {
			return err
		}
	}
	return nil
}
