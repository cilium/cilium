// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/workqueue"
	ctrl "sigs.k8s.io/controller-runtime"
)

type testRemoteObject struct {
	namespace string
	name      string
}

func (o testRemoteObject) NamespacedName() types.NamespacedName {
	return types.NamespacedName{Namespace: o.namespace, Name: o.name}
}

func requireRequest(t *testing.T, queue workqueue.TypedRateLimitingInterface[ctrl.Request], name string) {
	t.Helper()

	item, shutdown := queue.Get()
	require.False(t, shutdown)
	defer queue.Done(item)
	require.Equal(t, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "default", Name: name}}, item)
}

func TestRemoteObjectSource(t *testing.T) {
	src := NewRemoteObjectSource(
		NewEnqueueRequestForNamespacedNameFunc[NamespacedNamed](),
	)

	src.OnEvent(testRemoteObject{namespace: "default", name: "before-start"})

	queue := workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[ctrl.Request]())
	t.Cleanup(queue.ShutDown)
	require.NoError(t, src.Start(t.Context(), queue))
	require.Equal(t, 1, queue.Len())

	src.OnEvent(testRemoteObject{namespace: "default", name: "generic"})

	require.Equal(t, 2, queue.Len())
	requireRequest(t, queue, "before-start")
	requireRequest(t, queue, "generic")
	require.Zero(t, queue.Len())
}
