// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	"fmt"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/ipam/types"
)

const gcENIControllerName = "ipam-eni-gc"

var controllerManager = controller.NewManager()

type GarbageCollectionParams struct {
	// RunInterval is both the GC interval and also the minimum amount of time
	// an ENI has to be available before it is garbage collected
	RunInterval time.Duration
	// MaxPerInterval is the maximum number of ENIs which are deleted in a
	// single interval
	MaxPerInterval int32
	// ENITags is used to only garbage collect ENIs with this set of tags
	ENITags types.Tags
}

func StartENIGarbageCollector(ctx context.Context, api EC2API, params GarbageCollectionParams) {
	log.Info("Starting to garbage collect detached ENIs")

	var enisMarkedForDeletion []string
	controllerManager.UpdateController(gcENIControllerName, controller.ControllerParams{
		DoFunc: func(ctx context.Context) error {
			// Unfortunately, the EC2 API does not allow us to determine the age of
			// a network interface. To mitigate a race where Cilium just created a new
			// ENI to be attached to a node, we wait for one run interval before we delete
			// any ENIs. If the interface has been attached by the next run interval,
			// the deletion will fail and the interface will not be garbage collected.
			for _, eniID := range enisMarkedForDeletion {
				log.WithField("eniID", eniID).Debug("Garbage collecting ENI")
				err := api.DeleteNetworkInterface(ctx, eniID)
				if err != nil {
					log.WithError(err).Debug("Failed to garbage collect ENI")
				}
			}

			var err error
			enisMarkedForDeletion, err = api.GetDetachedNetworkInterfaces(ctx, params.ENITags, params.MaxPerInterval)
			if err != nil {
				return fmt.Errorf("failed to fetch available interfaces: %w", err)
			}

			if numENIs := len(enisMarkedForDeletion); numENIs > 0 {
				log.WithField("numInterfaces", numENIs).
					Debug("Marked unattached interfaces for garbage collection")
			}

			return nil
		},
		RunInterval: params.RunInterval,
		Context:     ctx,
	})
}
