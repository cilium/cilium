// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitygc

import (
	"context"
	"fmt"
	"strconv"
	"time"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/controller"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

var crdIdentityGCControllerGroup = controller.NewGroup("crd-identity-gc")

func (igc *GC) startCRDModeGC(ctx context.Context) error {
	if igc.gcInterval == 0 {
		igc.logger.Debug("CRD identity garbage collector disabled with interval set to 0")
		return nil
	}

	igc.logger.Info("Starting CRD identity garbage collector", logfields.Interval, igc.gcInterval)

	igc.mgr = controller.NewManager()
	igc.mgr.UpdateController("crd-identity-gc",
		controller.ControllerParams{
			Group:        crdIdentityGCControllerGroup,
			RunInterval:  igc.gcInterval,
			DoFunc:       igc.gc,
			NoErrorRetry: true,
		})

	return igc.wp.Submit("heartbeat-updater", igc.runHeartbeatUpdater)
}

func (igc *GC) runHeartbeatUpdater(ctx context.Context) error {
	for event := range igc.identity.Events(ctx) {
		switch event.Kind {
		case resource.Upsert:
			// Identity is marked as alive if it is new or it has
			// been updated.
			igc.heartbeatStore.markAlive(event.Object.Name, time.Now())
		case resource.Delete:
			// When the identity is deleted, delete the
			// heartbeat entry as well. This will not be
			// 100% accurate as the CiliumEndpoint can live
			// longer than the CiliumIdentity. See
			// heartbeatStore.gc()
			igc.heartbeatStore.delete(event.Object.Name)
		}
		event.Done(nil)
	}
	return nil
}

// gc is a single iteration of a garbage collection. It will
// delete identities that have not had its heartbeat lifesign updated
// since HeartbeatTimeout.
func (igc *GC) gc(ctx context.Context) error {
	igc.logger.Debug("Running CRD identity garbage collector")
	cepStore, err := igc.ciliumEndpoint.Store(ctx)
	if err != nil {
		igc.logger.Error("unable to get CEP store", logfields.Error, err)
		return err
	}
	identitiesStore, err := igc.identity.Store(ctx)
	if err != nil {
		igc.logger.Error("unable to get Cilium identities from local store", logfields.Error, err)
		return err
	}

	var idsInCESs map[string]bool
	cesEnabled := option.Config.EnableCiliumEndpointSlice
	if cesEnabled {
		cesStore, err := igc.ciliumEndpointSlice.Store(ctx)
		if err != nil {
			igc.logger.Warn("unable to get CES  store", logfields.Error, err)
		} else {
			idsInCESs = usedIdentitiesInCESs(cesStore)
		}
	}

	identities := identitiesStore.List()
	totalEntries := len(identities)
	deletedEntries := 0

	timeNow := time.Now()
	for _, identity := range identities {
		foundInCES := false
		if cesEnabled {
			_, foundInCES = idsInCESs[identity.Name]
		}
		// The identity is definitely alive if there's a CE or CES using it.
		alive := foundInCES || k8s.HasCEWithIdentity(cepStore, identity.Name)

		if alive {
			igc.heartbeatStore.markAlive(identity.Name, timeNow)
			continue
		}

		if !igc.heartbeatStore.isAlive(identity.Name) {
			ts, ok := identity.Annotations[identitybackend.HeartBeatAnnotation]
			if !ok {
				igc.logger.Info("Marking CRD identity for later deletion",
					logfields.Identity, identity.Name,
					logfields.K8sUID, identity.UID)

				// Deep copy so we get a version we are allowed to update
				identity = identity.DeepCopy()
				if identity.Annotations == nil {
					identity.Annotations = make(map[string]string)
				}

				identity.Annotations[identitybackend.HeartBeatAnnotation] = timeNow.Format(time.RFC3339Nano)
				if err := igc.updateIdentity(ctx, identity); err != nil {
					igc.logger.Error("Marking CRD identity for later deletion",
						logfields.Identity, identity,
						logfields.Error, err)
					return err
				}

				continue
			}

			igc.logger.Debug(fmt.Sprintf("Deleting unused CRD identity; marked for deletion at %s", ts),
				logfields.Identity, identity)

			err := igc.deleteIdentity(ctx, identity)
			if err != nil {
				if k8serrors.IsConflict(err) {
					// If a conflict arises, defer deletion to the next gc
					// run and permit gc to continue. This prevents
					// identities from accumulating if there are frequent
					// conflicts.
					igc.logger.Warn("Could not delete identity due to conflict",
						logfields.Identity, identity.Name,
						logfields.K8sUID, identity.UID)
					continue
				}

				igc.logger.Error("Deleting unused CRD identity",
					logfields.Identity, identity,
					logfields.Error, err,
				)
				return err
			} else {
				deletedEntries++
			}
		}

		// If Context was canceled we should break
		if ctx.Err() != nil {
			break
		}
	}

	if ctx.Err() == nil {
		igc.metrics.IdentityGCRuns.WithLabelValues(LabelValueOutcomeSuccess, LabelIdentityTypeCRD).Inc()
		igc.metrics.IdentityGCLatency.WithLabelValues(LabelValueOutcomeSuccess, LabelIdentityTypeCRD).Set(float64(time.Since(timeNow).Seconds()))
	} else {
		igc.metrics.IdentityGCRuns.WithLabelValues(LabelValueOutcomeFail, LabelIdentityTypeCRD).Inc()
		igc.metrics.IdentityGCLatency.WithLabelValues(LabelValueOutcomeFail, LabelIdentityTypeCRD).Set(float64(time.Since(timeNow).Seconds()))
	}
	aliveEntries := totalEntries - deletedEntries
	igc.metrics.IdentityGCSize.WithLabelValues(LabelValueOutcomeAlive, LabelIdentityTypeCRD).Set(float64(aliveEntries))
	igc.metrics.IdentityGCSize.WithLabelValues(LabelValueOutcomeDeleted, LabelIdentityTypeCRD).Set(float64(deletedEntries))

	igc.heartbeatStore.gc()

	return nil
}

// deleteIdentity deletes an identity. It includes the resource version and
// will error if the object has since been changed.
func (igc *GC) deleteIdentity(ctx context.Context, identity *v2.CiliumIdentity) error {
	// Wait until we can delete an identity
	if err := igc.rateLimiter.Wait(ctx); err != nil {
		return err
	}

	// Delete the identity from the auth identity store
	if err := igc.authIdentityClient.Delete(ctx, identity.Name); err != nil {
		return err
	}

	if err := igc.clientset.Delete(
		ctx,
		identity.Name,
		metav1.DeleteOptions{
			Preconditions: &metav1.Preconditions{
				UID:             &identity.UID,
				ResourceVersion: &identity.ResourceVersion,
			},
		},
	); err != nil {
		return err
	}

	igc.logger.Debug("Garbage collected CRD identity", logfields.Identity, identity.GetName())

	return nil
}

func (igc *GC) updateIdentity(ctx context.Context, identity *v2.CiliumIdentity) error {
	if _, err := igc.clientset.Update(
		ctx,
		identity,
		metav1.UpdateOptions{},
	); err != nil {
		return err
	}

	igc.logger.Debug("Updated CRD identity", logfields.Identity, identity.GetName())

	return nil
}

func usedIdentitiesInCESs(cesStore resource.Store[*v2alpha1.CiliumEndpointSlice]) map[string]bool {
	usedIdentities := make(map[string]bool)
	cesObjList := cesStore.List()
	for _, ces := range cesObjList {
		for _, cep := range ces.Endpoints {
			id := strconv.FormatInt(cep.IdentityID, 10)
			usedIdentities[id] = true
		}
	}
	return usedIdentities
}
