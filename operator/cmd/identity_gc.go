// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

func startKvstoreIdentityGC() {
	log.WithField(logfields.Interval, operatorOption.Config.IdentityGCInterval).Info("Starting kvstore identity garbage collector")
	backend, err := kvstoreallocator.NewKVStoreBackend(cache.IdentitiesPath, "", nil, kvstore.Client())
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize kvstore backend for identity allocation")
	}

	identity.InitMinMaxIdentityAllocation(option.Config)

	minID := idpool.ID(identity.MinimalAllocationIdentity)
	maxID := idpool.ID(identity.MaximumAllocationIdentity)

	log.WithFields(map[string]interface{}{
		"min":        minID,
		"max":        maxID,
		"cluster-id": option.Config.ClusterID,
	}).Info("Garbage Collecting identities between range")
	a := allocator.NewAllocatorForGC(backend, allocator.WithMin(minID), allocator.WithMax(maxID))

	successfulRuns := 0
	failedRuns := 0
	keysToDelete := map[string]uint64{}
	go func() {
		gcTimer, gcTimerDone := inctimer.New()
		defer gcTimerDone()
		for {
			now := time.Now()
			keysToDelete2, gcStats, err := a.RunGC(identityRateLimiter, keysToDelete)
			gcDuration := time.Since(now)
			if err != nil {
				log.WithError(err).Warning("Unable to run security identity garbage collector")

				if operatorOption.Config.EnableMetrics {
					failedRuns++
					metrics.IdentityGCRuns.WithLabelValues(metrics.LabelValueOutcomeFail).Set(float64(failedRuns))
				}
			} else {
				keysToDelete = keysToDelete2

				if operatorOption.Config.EnableMetrics {
					successfulRuns++
					metrics.IdentityGCRuns.WithLabelValues(metrics.LabelValueOutcomeSuccess).Set(float64(successfulRuns))

					metrics.IdentityGCSize.WithLabelValues("alive").Set(float64(gcStats.Alive))
					metrics.IdentityGCSize.WithLabelValues("deleted").Set(float64(gcStats.Deleted))
				}
			}

			sleep := operatorOption.Config.IdentityGCInterval
			if operatorOption.Config.IdentityGCInterval <= gcDuration {
				log.WithFields(logrus.Fields{
					logfields.Interval: operatorOption.Config.IdentityGCInterval,
					logfields.Duration: gcDuration,
					logfields.Hint:     "Is there a ratelimit configured on the kvstore client or server?",
				}).Warning("Identity garbage collection took longer than the GC interval")
				// Don't sleep because we have a lot of work to do.
			} else {
				sleep -= gcDuration
				<-gcTimer.After(sleep)
			}

			log.WithFields(logrus.Fields{
				"identities-to-delete": keysToDelete,
			}).Debug("Will delete identities if they are still unused")
		}
	}()
}
