// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package resource

import (
	"context"
	"sync"
	"testing"

	v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"

	"github.com/stretchr/testify/assert"
)

func TestFakeResource(t *testing.T) {
	type testObject = v1.PartialObjectMetadata
	var (
		objA = &testObject{ObjectMeta: v1.ObjectMeta{Name: "a", Namespace: "X"}}
		objB = &testObject{ObjectMeta: v1.ObjectMeta{Name: "b", Namespace: "X"}}
		objC = &testObject{ObjectMeta: v1.ObjectMeta{Name: "c", Namespace: "X"}}
	)

	f, _ := NewFakeResource[*testObject]()
	ctx, cancel := context.WithCancel(context.Background())
	events := f.Events(ctx)

	seq := []struct {
		kind EventKind
		obj  *testObject
	}{
		{Upsert, objA},
		{Upsert, objB},
		{Upsert, objC},
		{Sync, nil},
		{Delete, objC},
		{Delete, objA},
		{Delete, objB},
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, s := range seq {
			switch s.kind {
			case Upsert:
				f.EmitUpsert(s.obj)
			case Sync:
				f.EmitSync()
			case Delete:
				f.EmitDelete(s.obj)
			}
		}
	}()

	// Test events from empty state
	for _, s := range seq {
		ev := <-events
		assert.Equal(t, s.kind, ev.Kind)
		if s.obj != nil {
			assert.Equal(t, s.obj.Name, ev.Object.Name)
		}
	}
	wg.Wait()
	cancel()
	_, ok := <-events
	assert.False(t, ok)

	// Test replay of history
	ctx, cancel = context.WithCancel(context.Background())
	events = f.Events(ctx)
	for _, s := range seq {
		ev := <-events
		assert.Equal(t, s.kind, ev.Kind)
		if s.obj != nil {
			assert.Equal(t, s.obj.Name, ev.Object.Name)
		}
	}
	cancel()
	_, ok = <-events
	assert.False(t, ok)
}
