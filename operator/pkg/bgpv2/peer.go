// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"

	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8s_client "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/resiliency"
)

type peerConfigStatusReconciler struct {
	cs k8s_client.Clientset

	secretNamespace string
	secretResource  resource.Resource[*slim_core_v1.Secret]
	secretStore     resource.Store[*slim_core_v1.Secret]

	peerConfigResource resource.Resource[*v2.CiliumBGPPeerConfig]
	peerConfigStore    resource.Store[*v2.CiliumBGPPeerConfig]
}

type peerConfigStatusReconcilerIn struct {
	cell.In

	Clientset    k8s_client.Clientset
	DaemonConfig *option.DaemonConfig
	JobGroup     job.Group

	SecretResource     resource.Resource[*slim_core_v1.Secret]
	PeerConfigResource resource.Resource[*v2.CiliumBGPPeerConfig]
}

func registerPeerConfigStatusReconciler(in peerConfigStatusReconcilerIn) {
	if !in.DaemonConfig.BGPControlPlaneEnabled() {
		return
	}

	u := &peerConfigStatusReconciler{
		cs:                 in.Clientset,
		secretNamespace:    in.DaemonConfig.BGPSecretsNamespace,
		secretResource:     in.SecretResource,
		peerConfigResource: in.PeerConfigResource,
	}

	if !in.DaemonConfig.EnableBGPControlPlaneStatusReport {
		// Register a job to cleanup the conditions from the existing
		// PeerConfig resources. This is needed for the case that the
		// status report was enabled previously and some conditions
		// are already reported. Since we don't update the condition
		// anymore, remove all previously reported conditions to avoid
		// confusion.
		in.JobGroup.Add(job.OneShot(
			"cleanup-peer-config-status",
			u.cleanupStatus,
		))

		// When the status reporting is disabled, don't register the
		// status reconciler job.
		return
	}

	in.JobGroup.Add(job.OneShot(
		"peer-config-status-reconciler",
		u.reconcileStatus,
	))
}

func (u *peerConfigStatusReconciler) reconcileStatus(ctx context.Context, health cell.Health) error {
	ss, err := u.secretResource.Store(ctx)
	if err != nil {
		return err
	}
	u.secretStore = ss

	ps, err := u.peerConfigResource.Store(ctx)
	if err != nil {
		return err
	}
	u.peerConfigStore = ps

	se := u.secretResource.Events(ctx)
	pe := u.peerConfigResource.Events(ctx)

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
}

func (u *peerConfigStatusReconciler) cleanupStatus(ctx context.Context, health cell.Health) error {
	pcs, err := u.peerConfigResource.Store(ctx)
	if err != nil {
		return err
	}

	remaining := sets.New[resource.Key]()

	iter := pcs.IterKeys()
	for iter.Next() {
		remaining.Insert(iter.Key())
	}

	// Ensure all conditions managed by this
	// controller are removed from all resources.
	// Retry until we remove conditions from all
	// existing resources.
	err = resiliency.Retry(ctx, 3*time.Second, 20, func(ctx context.Context, _ int) (bool, error) {
		removed := sets.New[resource.Key]()

		for k := range remaining {
			pc, exists, err := pcs.GetByKey(k)
			if err != nil {
				// Failed to get the resource. Skip and retry.
				continue
			}

			// The resource doesn't exist anymore which is fine.
			if !exists {
				continue
			}

			updateStatus := false
			for _, cond := range v2.AllBGPPeerConfigConditions {
				if removed := meta.RemoveStatusCondition(&pc.Status.Conditions, cond); removed {
					updateStatus = true
				}
			}

			if updateStatus {
				if _, err := u.cs.CiliumV2().CiliumBGPPeerConfigs().UpdateStatus(ctx, pc, meta_v1.UpdateOptions{}); err != nil {
					// Failed to update status. Skip and retry.
					continue
				} else {
					removed.Insert(k)
				}
			}
		}

		remaining = remaining.Difference(removed)

		return len(remaining) == 0, nil
	})

	pcs.Release()

	// We use OK here since the semantics of Stopped() in the OneShot job is still undefined.
	if err == nil {
		health.OK("Cleanup job is done successfully")
	}

	return err
}

func (u *peerConfigStatusReconciler) reconcilePeerConfig(ctx context.Context, config *v2.CiliumBGPPeerConfig) error {
	updateStatus := false

	authSecretMissing := u.authSecretMissing(config)

	if changed := u.updateMissingAuthSecretCondition(config, authSecretMissing); changed {
		updateStatus = true
	}

	slices.SortStableFunc(config.Status.Conditions, func(a, b meta_v1.Condition) int {
		return strings.Compare(a.Type, b.Type)
	})

	if updateStatus {
		if _, err := u.cs.CiliumV2().CiliumBGPPeerConfigs().UpdateStatus(ctx, config, meta_v1.UpdateOptions{}); err != nil {
			return err
		}
	}

	return nil
}

func (u *peerConfigStatusReconciler) authSecretMissing(c *v2.CiliumBGPPeerConfig) bool {
	if c.Spec.AuthSecretRef == nil {
		return false
	}
	if _, exists, _ := u.secretStore.GetByKey(resource.Key{Namespace: u.secretNamespace, Name: *c.Spec.AuthSecretRef}); !exists {
		return true
	}
	return false
}

func (u *peerConfigStatusReconciler) updateMissingAuthSecretCondition(config *v2.CiliumBGPPeerConfig, missing bool) bool {
	cond := meta_v1.Condition{
		Type:               v2.BGPPeerConfigConditionMissingAuthSecret,
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
