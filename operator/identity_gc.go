// Copyright 2018-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"time"

	"github.com/cilium/cilium/operator/metrics"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

func startKvstoreIdentityGC() {
	log.WithField(logfields.Interval, operatorOption.Config.IdentityGCInterval).Info("Starting kvstore identity garbage collector")
	backend, err := kvstoreallocator.NewKVStoreBackend(cache.IdentitiesPath, "", nil, kvstore.Client())
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize kvstore backend for identity allocation")
	}
	a := allocator.NewAllocatorForGC(backend)

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
