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
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestUninitializedMetrics(t *testing.T) {
	enabledMetrics = nil
	podDeletionHandler = nil
	ProcessFlow(context.TODO(), &pb.Flow{})
	ProcessPodDeletion(&slim_corev1.Pod{})
}

func TestInitializedMetrics(t *testing.T) {
	t.Run("Should send pod removal to delayed delivery queue", func(t *testing.T) {
		pod := &slim_corev1.Pod{
			ObjectMeta: slim_metav1.ObjectMeta{
				Name: "name",
			},
		}
		enabledMetrics = &api.Handlers{}
		podDeletionHandler = &PodDeletionHandler{
			gracefulPeriod: 10 * time.Millisecond,
			queue:          workqueue.NewDelayingQueue(),
		}

		ProcessPodDeletion(pod)

		received, _ := podDeletionHandler.queue.Get()
		assert.Equal(t, pod, received)

		podDeletionHandler.queue.ShutDown()
	})

}
