// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/util/workqueue"

	pb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/types"
)

func TestUninitializedMetrics(t *testing.T) {
	enabledMetrics = nil
	endpointDeletionHandler = nil
	ProcessFlow(context.TODO(), &pb.Flow{})
	ProcessCiliumEndpointDeletion(&types.CiliumEndpoint{})
}

func TestInitializedMetrics(t *testing.T) {
	t.Run("Should send pod removal to delayed delivery queue", func(t *testing.T) {
		deletedEndpoint := &types.CiliumEndpoint{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name: "name",
			},
		}
		enabledMetrics = &api.Handlers{}
		endpointDeletionHandler = &CiliumEndpointDeletionHandler{
			gracefulPeriod: 10 * time.Millisecond,
			queue:          workqueue.NewDelayingQueue(),
		}

		ProcessCiliumEndpointDeletion(deletedEndpoint)

		received, _ := endpointDeletionHandler.queue.Get()
		assert.Equal(t, deletedEndpoint, received)

		endpointDeletionHandler.queue.ShutDown()
	})

}
