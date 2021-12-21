// SPDX-License-Identifier: Apache-2.0
// Copyright 2018-2020 Authors of Cilium

package main

import (
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
			keysToDelete2, gcStats, err := a.RunGC(identityRateLimiter, keysToDelete)
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
			<-gcTimer.After(operatorOption.Config.IdentityGCInterval)
			log.WithFields(logrus.Fields{
				"identities-to-delete": keysToDelete,
			}).Debug("Will delete identities if they are still unused")
		}
	}()
}
