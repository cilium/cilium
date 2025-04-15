// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitygc

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/allocator"
	ciliumIdentity "github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

func (igc *GC) startKVStoreModeGC(ctx context.Context) error {
	igc.logger.Info("Starting kvstore identity garbage collector", logfields.Interval, igc.gcInterval)
	backend, err := kvstoreallocator.NewKVStoreBackend(igc.logger, kvstoreallocator.KVStoreBackendConfiguration{BasePath: cache.IdentitiesPath, Backend: kvstore.Client()})
	if err != nil {
		return fmt.Errorf("unable to initialize kvstore backend for identity allocation")
	}

	minID := idpool.ID(ciliumIdentity.GetMinimalAllocationIdentity(igc.clusterInfo.ID))
	maxID := idpool.ID(ciliumIdentity.GetMaximumAllocationIdentity(igc.clusterInfo.ID))
	igc.logger.Info("Garbage Collecting kvstore identities between range",
		logfields.Min, minID,
		logfields.Max, maxID,
		logfields.ClusterID, igc.clusterInfo.ID)

	igc.allocator = allocator.NewAllocatorForGC(igc.logger, backend, allocator.WithMin(minID), allocator.WithMax(maxID))

	return igc.wp.Submit("kvstore-identity-gc", igc.runKVStoreModeGC)
}

func (igc *GC) runKVStoreModeGC(ctx context.Context) error {
	keysToDeletePrev := map[string]uint64{}

	for {
		now := time.Now()

		keysToDelete, gcStats, err := igc.allocator.RunGC(ctx, igc.rateLimiter, keysToDeletePrev)
		gcDuration := time.Since(now)
		if err != nil {
			igc.logger.Warn("Unable to run kvstore security identity garbage collector", logfields.Error, err)
			igc.metrics.IdentityGCRuns.WithLabelValues(LabelValueOutcomeFail, LabelIdentityTypeKVStore).Inc()
			igc.metrics.IdentityGCLatency.WithLabelValues(LabelValueOutcomeFail, LabelIdentityTypeKVStore).Set(float64(time.Since(now).Seconds()))
		} else {
			// Best effort to run auth identity GC
			err = igc.runAuthGC(ctx, keysToDeletePrev)
			if err != nil {
				igc.logger.Warn("Unable to run kvstore auth identity garbage collector",
					logfields.IdentitiesToDelete, keysToDeletePrev,
					logfields.Error, err)
			}

			keysToDeletePrev = keysToDelete

			igc.metrics.IdentityGCRuns.WithLabelValues(LabelValueOutcomeSuccess, LabelIdentityTypeKVStore).Inc()

			igc.metrics.IdentityGCSize.WithLabelValues(LabelValueOutcomeAlive, LabelIdentityTypeKVStore).Set(float64(gcStats.Alive))
			igc.metrics.IdentityGCSize.WithLabelValues(LabelValueOutcomeDeleted, LabelIdentityTypeKVStore).Set(float64(gcStats.Deleted))
			igc.metrics.IdentityGCLatency.WithLabelValues(LabelValueOutcomeSuccess, LabelIdentityTypeKVStore).Set(float64(time.Since(now).Seconds()))
		}

		if igc.gcInterval <= gcDuration {
			igc.logger.Warn("Kvstore Identity garbage collection took longer than the GC interval",
				logfields.Interval, igc.gcInterval,
				logfields.Duration, gcDuration,
				logfields.Hint, "Is there a ratelimit configured on the kvstore client or server?")

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
			case <-time.After(igc.gcInterval - gcDuration):
			}
		}

		igc.logger.Debug(
			"Will delete kvstore identities if they are still unused",
			logfields.IdentitiesToDelete, keysToDeletePrev)
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
