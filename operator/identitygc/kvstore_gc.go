// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitygc

import (
	"context"
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/allocator"
	ciliumIdentity "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (igc *GC) startKVStoreModeGC(ctx context.Context) error {
	log.WithField(logfields.Interval, igc.gcInterval).Info("Starting kvstore identity garbage collector")
	backend, err := kvstoreallocator.NewKVStoreBackend(cache.IdentitiesPath, "", nil, kvstore.Client())
	if err != nil {
		return fmt.Errorf("unable to initialize kvstore backend for identity allocation")
	}

	minID := idpool.ID(ciliumIdentity.GetMinimalAllocationIdentity())
	maxID := idpool.ID(ciliumIdentity.GetMaximumAllocationIdentity())
	log.WithFields(map[string]interface{}{
		"min":        minID,
		"max":        maxID,
		"cluster-id": igc.clusterInfo.ID,
	}).Info("Garbage Collecting identities between range")

	igc.allocator = allocator.NewAllocatorForGC(backend, allocator.WithMin(minID), allocator.WithMax(maxID))

	return igc.wp.Submit("kvstore-identity-gc", igc.runKVStoreModeGC)
}

func (igc *GC) runKVStoreModeGC(ctx context.Context) error {
	keysToDeletePrev := map[string]uint64{}

	gcTimer, gcTimerDone := inctimer.New()
	defer gcTimerDone()
	for {
		now := time.Now()

		keysToDelete, gcStats, err := igc.allocator.RunGC(igc.rateLimiter, keysToDeletePrev)
		gcDuration := time.Since(now)
		if err != nil {
			igc.logger.WithError(err).Warning("Unable to run security identity garbage collector")

			igc.failedRuns++
			igc.metrics.IdentityGCRuns.WithLabelValues(LabelValueOutcomeFail).Set(float64(igc.failedRuns))
		} else {
			// Best effort to run auth identity GC
			err = igc.runAuthGC(ctx, keysToDeletePrev)
			if err != nil {
				igc.logger.WithField("identities-to-delete", keysToDeletePrev).
					WithError(err).
					Warning("Unable to run auth identity garbage collector")
			}

			keysToDeletePrev = keysToDelete

			igc.successfulRuns++
			igc.metrics.IdentityGCRuns.WithLabelValues(LabelValueOutcomeSuccess).Set(float64(igc.successfulRuns))

			igc.metrics.IdentityGCSize.WithLabelValues(LabelValueOutcomeAlive).Set(float64(gcStats.Alive))
			igc.metrics.IdentityGCSize.WithLabelValues(LabelValueOutcomeDeleted).Set(float64(gcStats.Deleted))
		}

		if igc.gcInterval <= gcDuration {
			igc.logger.WithFields(logrus.Fields{
				logfields.Interval: igc.gcInterval,
				logfields.Duration: gcDuration,
				logfields.Hint:     "Is there a ratelimit configured on the kvstore client or server?",
			}).Warning("Identity garbage collection took longer than the GC interval")

			// Don't sleep because we have a lot of work to do,
			// but check if the context was canceled before running
			// another gc cycle.
			if ctx.Err() != nil {
				return nil
			}
		} else {
			select {
			case <-ctx.Done():
				return nil
			case <-gcTimer.After(igc.gcInterval - gcDuration):
			}
		}

		igc.logger.WithFields(logrus.Fields{
			"identities-to-delete": keysToDeletePrev,
		}).Debug("Will delete identities if they are still unused")
	}
}

func (igc *GC) runAuthGC(ctx context.Context, staleKeys map[string]uint64) error {
	// Wait until we can delete an identity
	if err := igc.rateLimiter.Wait(ctx); err != nil {
		return err
	}

	for k := range staleKeys {
		if err := igc.authIdentityClient.Delete(ctx, k); err != nil {
			return err
		}
	}
	return nil
}
