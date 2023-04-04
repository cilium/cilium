// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitygc

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/operator/metrics"
	"github.com/cilium/cilium/operator/watchers"
	"github.com/cilium/cilium/pkg/controller"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/identitybackend"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (igc *GC) startCRDModeGC(ctx context.Context) error {
	if igc.gcInterval == 0 {
		igc.logger.Debug("CRD identity garbage collector disabled with interval set to 0")
		return nil
	}

	igc.logger.WithField(logfields.Interval, igc.gcInterval).Info("Starting CRD identity garbage collector")

	igc.mgr = controller.NewManager()
	igc.mgr.UpdateController("crd-identity-gc",
		controller.ControllerParams{
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

	select {
	case <-watchers.CiliumEndpointsSynced:
	case <-ctx.Done():
		return nil
	}

	identitiesStore, err := igc.identity.Store(ctx)
	if err != nil {
		igc.logger.WithError(err).Error("unable to get Cilium identities from local store")
		return err
	}
	identities := identitiesStore.List()
	totalEntries := len(identities)
	deletedEntries := 0

	timeNow := time.Now()
	for _, identity := range identities {
		// The identity is definitely alive if there's a CE using it.
		if watchers.HasCEWithIdentity(identity.Name) {
			igc.heartbeatStore.markAlive(identity.Name, timeNow)
			continue
		}

		if !igc.heartbeatStore.isAlive(identity.Name) {
			ts, ok := identity.Annotations[identitybackend.HeartBeatAnnotation]
			if !ok {
				log.WithFields(logrus.Fields{
					logfields.Identity: identity.Name,
					logfields.K8sUID:   identity.UID,
				}).Info("Marking identity for later deletion")

				// Deep copy so we get a version we are allowed to update
				identity = identity.DeepCopy()
				if identity.Annotations == nil {
					identity.Annotations = make(map[string]string)
				}

				identity.Annotations[identitybackend.HeartBeatAnnotation] = timeNow.Format(time.RFC3339Nano)
				if err := igc.updateIdentity(ctx, identity); err != nil {
					log.WithError(err).
						WithField(logfields.Identity, identity).
						Error("Marking identity for later deletion")
					return err
				}

				continue
			}

			log.WithFields(logrus.Fields{
				logfields.Identity: identity,
			}).Debugf("Deleting unused identity; marked for deletion at %s", ts)

			if err := igc.deleteIdentity(ctx, identity); err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					logfields.Identity: identity,
				}).Error("Deleting unused identity")
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

	if igc.enableMetrics {
		if ctx.Err() == nil {
			igc.successfulRuns++
			metrics.IdentityGCRuns.WithLabelValues(metrics.LabelValueOutcomeSuccess).Set(float64(igc.successfulRuns))
		} else {
			igc.failedRuns++
			metrics.IdentityGCRuns.WithLabelValues(metrics.LabelValueOutcomeFail).Set(float64(igc.failedRuns))
		}
		aliveEntries := totalEntries - deletedEntries
		metrics.IdentityGCSize.WithLabelValues(metrics.LabelValueOutcomeAlive).Set(float64(aliveEntries))
		metrics.IdentityGCSize.WithLabelValues(metrics.LabelValueOutcomeDeleted).Set(float64(deletedEntries))
	}

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

	log.WithField(logfields.Identity, identity.GetName()).Debug("Garbage collected identity")

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

	log.WithField(logfields.Identity, identity.GetName()).Debug("Updated identity")

	return nil
}
