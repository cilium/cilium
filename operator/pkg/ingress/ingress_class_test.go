// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingress

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func Test_ingressClassSyncCanExit(t *testing.T) {
	_, cs := k8sClient.NewFakeClientset()
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	var ingressClasses resource.Resource[*slim_networkingv1.IngressClass]

	h := hive.New(
		cell.Provide(func() k8sClient.Clientset { return cs }),
		cell.Provide(k8s.IngressClassResource),
		cell.Invoke(func(r resource.Resource[*slim_networkingv1.IngressClass]) {
			ingressClasses = r
		}),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := h.Start(ctx); err != nil {
		t.Fatalf("hive.start failed: %s", err)
	}

	i := newIngressClassManager(queue, ingressClasses)

	// Start the ingressClassManager
	go i.Run(ctx)

	// Wait for an initial sync.
	if err := i.WaitForSync(ctx); err != nil {
		t.Fatalf("unexpected error while doing initial sync: %s", err)
	}
	assert.True(t, i.synced.Load())

	// This second sync should not block.
	if err := i.WaitForSync(ctx); err != nil {
		t.Fatalf("unexpected error while doing second sync: %s", err)
	}

	// Try exiting a sync using context
	testCtx, testCancel := context.WithCancel(ctx)
	testCancel()
	i.synced.Store(false)

	if err := i.WaitForSync(testCtx); err == nil {
		t.Fatalf("unexpected nil error while doing forced block sync: %s", err)
	} else if !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected error while doing forced block sync, wanted context.Canceled: %s", err)
	}

	assert.Nil(t, h.Stop(ctx))
}

func Test_ingressClassIgnoresNonCilium(t *testing.T) {
	_, cs := k8sClient.NewFakeClientset()
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

	var ingressClasses resource.Resource[*slim_networkingv1.IngressClass]

	h := hive.New(
		cell.Provide(func() k8sClient.Clientset { return cs }),
		cell.Provide(k8s.IngressClassResource),
		cell.Invoke(func(r resource.Resource[*slim_networkingv1.IngressClass]) {
			ingressClasses = r
		}),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := h.Start(ctx); err != nil {
		t.Fatalf("hive.start failed: %s", err)
	}

	i := newIngressClassManager(queue, ingressClasses)

	nonCiliumIngressClass := &slim_networkingv1.IngressClass{
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:            "my-name-is-not-cilium",
			ResourceVersion: "0",
		},
	}

	err := i.handleDeleteEvent(
		resource.Event[*slim_networkingv1.IngressClass]{
			Kind:   resource.Delete,
			Object: nonCiliumIngressClass,
			Done:   func(_ error) {},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error handling delete event for non-cilium IngressClass: %s", err)
	}

	assert.Equal(t, 0, queue.Len())

	err = i.handleUpsertEvent(
		resource.Event[*slim_networkingv1.IngressClass]{
			Kind:   resource.Upsert,
			Object: nonCiliumIngressClass,
			Done:   func(_ error) {},
		},
	)
	if err != nil {
		t.Fatalf("unexpected error handling upsert event for non-cilium IngressClass: %s", err)
	}

	assert.Equal(t, 0, queue.Len())

	assert.Nil(t, h.Stop(ctx))
}

func Test_ingressClassHandleEvent(t *testing.T) {
	type testCase struct {
		desc                 string
		class                *slim_networkingv1.IngressClass
		classMod             func(i slim_networkingv1.IngressClass) slim_networkingv1.IngressClass
		doDelete             bool
		defaultAtStart       bool
		defaultAfterMod      bool
		expectedStartEvent   interface{}
		expectedModEvent     interface{}
		expectedRestoreEvent interface{}
	}

	cases := []testCase{
		{
			desc: "become default, false to true",
			class: &slim_networkingv1.IngressClass{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            ciliumIngressClassName,
					ResourceVersion: "0",
					Annotations: map[string]string{
						slim_networkingv1.AnnotationIsDefaultIngressClass: "false",
						"test": "false-to-true",
					},
				},
			},
			classMod: func(i slim_networkingv1.IngressClass) slim_networkingv1.IngressClass {
				i.ObjectMeta.Annotations[slim_networkingv1.AnnotationIsDefaultIngressClass] = "true"
				return i
			},
			defaultAtStart:  false,
			defaultAfterMod: true,
			expectedStartEvent: ciliumIngressClassUpdatedEvent{
				isDefault: false,
				changed:   false,
			},
			expectedModEvent: ciliumIngressClassUpdatedEvent{
				isDefault: true,
				changed:   true,
			},
			expectedRestoreEvent: ciliumIngressClassUpdatedEvent{
				isDefault: false,
				changed:   true,
			},
		},
		{
			desc: "become default, none to true",
			class: &slim_networkingv1.IngressClass{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            ciliumIngressClassName,
					ResourceVersion: "0",
					Annotations: map[string]string{
						"test": "none-to-true",
					},
				},
			},
			classMod: func(i slim_networkingv1.IngressClass) slim_networkingv1.IngressClass {
				i.ObjectMeta.Annotations[slim_networkingv1.AnnotationIsDefaultIngressClass] = "true"

				return i
			},
			defaultAtStart:  false,
			defaultAfterMod: true,
			expectedStartEvent: ciliumIngressClassUpdatedEvent{
				isDefault: false,
				changed:   false,
			},
			expectedModEvent: ciliumIngressClassUpdatedEvent{
				isDefault: true,
				changed:   true,
			},
			expectedRestoreEvent: ciliumIngressClassUpdatedEvent{
				isDefault: false,
				changed:   true,
			},
		},
		{
			desc: "stay default",
			class: &slim_networkingv1.IngressClass{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            ciliumIngressClassName,
					ResourceVersion: "0",
					Annotations: map[string]string{
						slim_networkingv1.AnnotationIsDefaultIngressClass: "true",
						"test": "stay-default",
					},
				},
			},
			classMod: func(i slim_networkingv1.IngressClass) slim_networkingv1.IngressClass {
				return i
			},
			defaultAtStart:  true,
			defaultAfterMod: true,
			expectedStartEvent: ciliumIngressClassUpdatedEvent{
				isDefault: true,
				changed:   true,
			},
			expectedModEvent: ciliumIngressClassUpdatedEvent{
				isDefault: true,
				changed:   false,
			},
			expectedRestoreEvent: ciliumIngressClassUpdatedEvent{
				isDefault: true,
				changed:   false,
			},
		},
		{
			desc: "become non-default, true to false",
			class: &slim_networkingv1.IngressClass{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            ciliumIngressClassName,
					ResourceVersion: "0",
					Annotations: map[string]string{
						slim_networkingv1.AnnotationIsDefaultIngressClass: "true",
						"test": "true-to-false",
					},
				},
			},
			classMod: func(i slim_networkingv1.IngressClass) slim_networkingv1.IngressClass {
				i.ObjectMeta.Annotations[slim_networkingv1.AnnotationIsDefaultIngressClass] = "false"

				return i
			},
			defaultAtStart:  true,
			defaultAfterMod: false,
			expectedStartEvent: ciliumIngressClassUpdatedEvent{
				isDefault: true,
				changed:   true,
			},
			expectedModEvent: ciliumIngressClassUpdatedEvent{
				isDefault: false,
				changed:   true,
			},
			expectedRestoreEvent: ciliumIngressClassUpdatedEvent{
				isDefault: true,
				changed:   true,
			},
		},
		{
			desc: "become non-default, true to none",
			class: &slim_networkingv1.IngressClass{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            ciliumIngressClassName,
					ResourceVersion: "0",
					Annotations: map[string]string{
						slim_networkingv1.AnnotationIsDefaultIngressClass: "true",
						"test": "true-to-none",
					},
				},
			},
			classMod: func(i slim_networkingv1.IngressClass) slim_networkingv1.IngressClass {
				delete(i.ObjectMeta.Annotations, slim_networkingv1.AnnotationIsDefaultIngressClass)

				return i
			},
			defaultAtStart:  true,
			defaultAfterMod: false,
			expectedStartEvent: ciliumIngressClassUpdatedEvent{
				isDefault: true,
				changed:   true,
			},
			expectedModEvent: ciliumIngressClassUpdatedEvent{
				isDefault: false,
				changed:   true,
			},
			expectedRestoreEvent: ciliumIngressClassUpdatedEvent{
				isDefault: true,
				changed:   true,
			},
		},
		{
			desc: "stay non-default",
			class: &slim_networkingv1.IngressClass{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            ciliumIngressClassName,
					ResourceVersion: "0",
					Annotations: map[string]string{
						slim_networkingv1.AnnotationIsDefaultIngressClass: "false",
						"test": "stay-non-default",
					},
				},
			},
			classMod: func(i slim_networkingv1.IngressClass) slim_networkingv1.IngressClass {
				return i
			},
			defaultAtStart:  false,
			defaultAfterMod: false,
			expectedStartEvent: ciliumIngressClassUpdatedEvent{
				isDefault: false,
				changed:   false,
			},
			expectedModEvent: ciliumIngressClassUpdatedEvent{
				isDefault: false,
				changed:   false,
			},
			expectedRestoreEvent: ciliumIngressClassUpdatedEvent{
				isDefault: false,
				changed:   false,
			},
		},
		{
			desc: "delete default",
			class: &slim_networkingv1.IngressClass{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            ciliumIngressClassName,
					ResourceVersion: "0",
					Annotations: map[string]string{
						slim_networkingv1.AnnotationIsDefaultIngressClass: "true",
						"test": "delete-default",
					},
				},
			},
			doDelete:       true,
			defaultAtStart: true,
			expectedStartEvent: ciliumIngressClassUpdatedEvent{
				isDefault: true,
				changed:   true,
			},
			expectedModEvent: ciliumIngressClassDeletedEvent{
				wasDefault: true,
			},
			expectedRestoreEvent: ciliumIngressClassUpdatedEvent{
				isDefault: true,
				changed:   true,
			},
		},
		{
			desc: "delete non-default",
			class: &slim_networkingv1.IngressClass{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            ciliumIngressClassName,
					ResourceVersion: "0",
					Annotations: map[string]string{
						slim_networkingv1.AnnotationIsDefaultIngressClass: "false",
						"test": "delete-non-default",
					},
				},
			},
			doDelete:       true,
			defaultAtStart: false,
			expectedStartEvent: ciliumIngressClassUpdatedEvent{
				isDefault: false,
				changed:   false,
			},
			expectedModEvent: ciliumIngressClassDeletedEvent{
				wasDefault: false,
			},
			expectedRestoreEvent: ciliumIngressClassUpdatedEvent{
				isDefault: false,
				changed:   false,
			},
		},
		{
			desc: "fix bad annotation value",
			class: &slim_networkingv1.IngressClass{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            ciliumIngressClassName,
					ResourceVersion: "0",
					Annotations: map[string]string{
						"test": "fix-bad-annotation",
						slim_networkingv1.AnnotationIsDefaultIngressClass: "notabool",
					},
				},
			},
			classMod: func(i slim_networkingv1.IngressClass) slim_networkingv1.IngressClass {
				i.ObjectMeta.Annotations[slim_networkingv1.AnnotationIsDefaultIngressClass] = "true"
				return i
			},
			defaultAtStart:  false,
			defaultAfterMod: true,
			expectedStartEvent: ciliumIngressClassUpdatedEvent{
				isDefault: false,
				changed:   false,
			},
			expectedModEvent: ciliumIngressClassUpdatedEvent{
				isDefault: true,
				changed:   true,
			},
			expectedRestoreEvent: ciliumIngressClassUpdatedEvent{
				isDefault: false,
				changed:   true,
			},
		},
		{
			desc: "apply bad annotation value",
			class: &slim_networkingv1.IngressClass{
				ObjectMeta: slim_metav1.ObjectMeta{
					Name:            ciliumIngressClassName,
					ResourceVersion: "0",
					Annotations: map[string]string{
						"test": "apply-bad-annotation",
						slim_networkingv1.AnnotationIsDefaultIngressClass: "true",
					},
				},
			},
			classMod: func(i slim_networkingv1.IngressClass) slim_networkingv1.IngressClass {
				i.ObjectMeta.Annotations[slim_networkingv1.AnnotationIsDefaultIngressClass] = "notabool"
				return i
			},
			defaultAtStart:  true,
			defaultAfterMod: false,
			expectedStartEvent: ciliumIngressClassUpdatedEvent{
				isDefault: true,
				changed:   true,
			},
			expectedModEvent: ciliumIngressClassUpdatedEvent{
				isDefault: false,
				changed:   true,
			},
			expectedRestoreEvent: ciliumIngressClassUpdatedEvent{
				isDefault: true,
				changed:   true,
			},
		},
	}

	handleEventExpectation := func(
		t *testing.T, expectedEvent interface{}, queue workqueue.RateLimitingInterface,
	) {
		e, _ := queue.Get()
		log.WithField("queue-event", e).Warn("Got event from test queue")

		switch receivedEvent := e.(type) {
		case ciliumIngressClassUpdatedEvent:
			switch expectedEvent := expectedEvent.(type) {
			case ciliumIngressClassUpdatedEvent:
				assert.Equal(t, expectedEvent.isDefault, receivedEvent.isDefault)
				assert.Equal(t, expectedEvent.changed, receivedEvent.changed)
			default:
				t.Fatalf("expected ciliumIngressClassUpdatedEvent, got %+v", receivedEvent)
			}
		case ciliumIngressClassDeletedEvent:
			switch expectedEvent := expectedEvent.(type) {
			case ciliumIngressClassDeletedEvent:
				assert.Equal(t, expectedEvent.wasDefault, receivedEvent.wasDefault)
			default:
				t.Fatalf("expected ciliumIngressClassDeletedEvent, got %+v", receivedEvent)
			}
		default:
			t.Fatalf("unknown event: %+v", receivedEvent)
		}

		queue.Forget(e)
		queue.Done(e)
	}

	runTestCase := func(t *testing.T, c testCase) {
		fakeClient, cs := k8sClient.NewFakeClientset()
		ingressClassesClient := cs.Slim().NetworkingV1().IngressClasses()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())

		var ingressClasses resource.Resource[*slim_networkingv1.IngressClass]

		// Create the first IngressClass
		// Do this first to avoid a race condition
		fakeClient.SlimFakeClientset.Tracker().Create(
			slim_networkingv1.SchemeGroupVersion.WithResource("ingressclasses"), c.class, "",
		)

		h := hive.New(
			cell.Provide(func() k8sClient.Clientset { return cs }),
			cell.Provide(k8s.IngressClassResource),
			cell.Invoke(func(r resource.Resource[*slim_networkingv1.IngressClass]) {
				ingressClasses = r
			}),
		)

		if err := h.Start(ctx); err != nil {
			t.Fatalf("hive.start failed: %s", err)
		}

		i := newIngressClassManager(queue, ingressClasses)

		// Start the class manager
		go i.Run(ctx)

		if err := i.WaitForSync(ctx); err != nil {
			t.Fatalf("unexpected error while running WaitForSync: %s", err)
		}

		// Handle our initial expectations before modifications
		handleEventExpectation(t, c.expectedStartEvent, queue)
		assert.Equal(t, c.defaultAtStart, i.IsDefault())

		// Now adjust the IngressClass based on the test case
		if c.classMod != nil {
			newClass := c.classMod(*c.class.DeepCopy())
			ingressClassesClient.Update(ctx, &newClass, v1.UpdateOptions{})
		}

		if c.doDelete {
			ingressClassesClient.Delete(ctx, c.class.Name, v1.DeleteOptions{})
		}

		handleEventExpectation(t, c.expectedModEvent, queue)

		if c.doDelete {
			assert.False(t, i.IsDefault())
		} else {
			assert.Equal(t, c.defaultAfterMod, i.IsDefault())
		}

		// Restore the original Ingress Class
		if c.classMod != nil {
			ingressClassesClient.Update(ctx, c.class, v1.UpdateOptions{})
		}

		if c.doDelete {
			ingressClassesClient.Create(ctx, c.class, v1.CreateOptions{})
		}

		handleEventExpectation(t, c.expectedRestoreEvent, queue)
		assert.Equal(t, c.defaultAtStart, i.IsDefault())

		assert.Nil(t, h.Stop(ctx))
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			runTestCase(t, c)
		})
	}
}
