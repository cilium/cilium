// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sRuntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
)

// transformOf returns the cache.TransformFunc which WithTransform wraps the
// given transform into, as the resource itself only exposes it to the informer.
func transformOf[From, To k8sRuntime.Object](t *testing.T, transform func(From) (To, error)) (cache.TransformFunc, func() k8sRuntime.Object) {
	t.Helper()

	var o options
	WithTransform(transform)(&o)
	require.NotNil(t, o.transform)
	require.NotNil(t, o.sourceObj)
	return o.transform, o.sourceObj
}

func testPod(name string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
	}
}

// stripPod is a cross-type transform: the store ends up holding a type which
// differs from the one the informer decodes.
func stripPod(pod *corev1.Pod) (*metav1.PartialObjectMetadata, error) {
	return &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: pod.Name}}, nil
}

func TestTransformDelta(t *testing.T) {
	transform, _ := transformOf(t, stripPod)

	// A freshly decoded object is transformed.
	obj, err := transformDelta(transform, testPod("foo"))
	require.NoError(t, err)
	assert.Equal(t, &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{Name: "foo"}}, obj)

	// A resource without a transform passes everything through.
	pod := testPod("foo")
	obj, err = transformDelta(nil, pod)
	require.NoError(t, err)
	assert.Same(t, pod, obj)
}

// The object of a tombstone is never read, and is not one the transform can
// make any assumption about, so it is dropped and only the key is kept.
func TestTransformDeltaTombstone(t *testing.T) {
	transform, _ := transformOf(t, stripPod)

	for name, tombstone := range map[string]cache.DeletedFinalStateUnknown{
		// Taken from a delta still queued for the key: a raw object, which the
		// same batch of deltas is also about to transform.
		"queued delta": {Key: "default/foo", Obj: testPod("foo")},
		// Taken from the store: already transformed, and still readable by the
		// subscribers of the resource.
		"store": {Key: "default/foo", Obj: &metav1.PartialObjectMetadata{
			ObjectMeta: metav1.ObjectMeta{Name: "foo"},
		}},
		// The lookup of the object in the store failed.
		"no object": {Key: "default/foo", Obj: nil},
	} {
		t.Run(name, func(t *testing.T) {
			obj, err := transformDelta(transform, tombstone)
			require.NoError(t, err)
			assert.Equal(t, cache.DeletedFinalStateUnknown{Key: "default/foo"}, obj)

			// Whichever it held, the key is all the resource needs of it.
			assert.Equal(t, Key{Name: "foo", Namespace: "default"}, NewKey(obj))
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			require.NoError(t, err)
			assert.Equal(t, "default/foo", key)
		})
	}
}
