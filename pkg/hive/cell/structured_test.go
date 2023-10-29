// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/lock"
)

func init() {
	reporterMinTimeout = time.Millisecond * 10
}

func createRoot(hr statusNodeReporter) (Scope, func()) {
	s := rootScope(FullModuleID{"root.foo"}, hr)
	s.start()
	return s, func() {
		flushAndClose(s, "test is done")
	}
}

func createMockReporter(assert *assert.Assertions) (*mockReporter, func(), func(), func()) {

	l := new(lock.Mutex)
	last := new(Level)
	*last = StatusUnknown
	hr := &mockReporter{
		ok: func(s string) {
			l.Lock()
			defer l.Unlock()
			*last = StatusOK
		},
		degraded: func(s string) {
			l.Lock()
			defer l.Unlock()
			*last = StatusDegraded
		},
		stopped: func(s string) {
			l.Lock()
			defer l.Unlock()
			*last = StatusStopped
		},
	}

	assertOK := func() {
		assert.Eventually(func() bool {
			l.Lock()
			defer l.Unlock()
			return *last == StatusOK
		}, time.Second*5, time.Millisecond*10)
	}
	assertDegraded := func() {
		assert.Eventually(func() bool {
			l.Lock()
			defer l.Unlock()
			return *last == StatusDegraded
		}, time.Second*5, time.Millisecond*10)
	}
	assertUnknown := func() {
		assert.Eventually(func() bool {
			l.Lock()
			defer l.Unlock()
			return *last == StatusUnknown
		}, time.Second*5, time.Millisecond*10)
	}
	return hr, assertOK, assertDegraded, assertUnknown
}

func TestCloseEmpty(t *testing.T) {
	hr, _, _, assertUnknown := createMockReporter(assert.New(t))
	_, done := createRoot(hr)
	defer done()
	assertUnknown()
}

func TestReporterV2(t *testing.T) {
	hr, assertOk, assertDegraded, _ := createMockReporter(assert.New(t))
	s, done := createRoot(hr)
	defer done()

	hs := GetSubScope(s, "test_scope")
	hs2 := GetSubScope(s, "test_scope2")
	GetHealthReporter(hs2, "foo").OK("ok")
	GetHealthReporter(hs, "test").OK("ok")
	GetHealthReporter(hs, "test").OK("ok")
	assertOk()
	GetHealthReporter(hs, "test").Degraded("oops", nil)
	assertDegraded()
}

func TestSubreporter(t *testing.T) {
	hr, assertOK, assertDegraded, _ := createMockReporter(assert.New(t))
	s, done := createRoot(hr)
	defer done()

	fooScope := GetSubScope(s, "foo")
	GetHealthReporter(fooScope, "1").OK("ok")
	GetHealthReporter(fooScope, "2").OK("ok")
	GetHealthReporter(fooScope, "3").OK("ok")
	assertOK()
	GetHealthReporter(fooScope, "1").Degraded("oops", nil)
	assertDegraded()
	GetHealthReporter(fooScope, "1").Stopped("")
	assertOK()

	foo2Scope := GetSubScope(s, "foo2")
	GetHealthReporter(foo2Scope, "1").OK("ok")
	assertOK()
	barScope := GetSubScope(s, "bar")
	GetHealthReporter(barScope, "1").Degraded("boom", nil)
	assertDegraded()
	GetHealthReporter(barScope, "1").Stopped("")
	assertOK()
}

func TestStructuredReporterCancel(t *testing.T) {
	hr, assertOK, assertDegraded, _ := createMockReporter(assert.New(t))
	s, done := createRoot(hr)
	defer done()

	epmScope := GetSubScope(s, "endpoint-manager")
	ep000Scope := GetSubScope(epmScope, "endpoint-000")
	GetHealthReporter(ep000Scope, "k8s-sync").Degraded("nooo", nil)
	GetHealthReporter(ep000Scope, "k8s-sync2").OK("nooo")
	assertDegraded()
	GetHealthReporter(ep000Scope, "k8s-sync").Stopped("no more")
	assertOK()
}

func TestWithBaseReporter(t *testing.T) {
	hr, assertOK, assertDegraded, _ := createMockReporter(assert.New(t))
	s, done := createRoot(hr)
	defer done()
	GetHealthReporter(s, "test").OK("")
	assertOK()
	GetHealthReporter(s, "test").Degraded("", nil)
	assertDegraded()
}

func TestStopped(t *testing.T) {
	hr, assertOK, assertDegraded, _ := createMockReporter(assert.New(t))
	var s Scope
	s, done := createRoot(hr)
	defer done()
	s = GetSubScope(s, "foo")
	GetHealthReporter(s, "test").Degraded("", nil)
	assertDegraded()
	GetHealthReporter(s, "test").Stopped("")
	assertOK()
}

// This test validates that:
//  1. A scope that is orphaned and then garbage collected, that satisifies the
//     constraint that it or none of its children are referenced, is removed.
func TestUnreferencedScope(t *testing.T) {
	assert := assert.New(t)
	hr, assertOK, _, assertUnknown := createMockReporter(assert)
	r, done := createRoot(hr)
	defer done()

	// Create two orphaned scopes, one is a child of the other.
	func() {
		type closureScope struct {
			s Scope
		}
		c := &closureScope{s: GetSubScope(GetSubScope(r, "orphan0"), "orphan1")}
		// This temporarily prevents the scope from being garbage collected so
		// we can validate the base reporter graph.
		runtime.SetFinalizer(c, func(s *closureScope) {})
		defer runtime.SetFinalizer(c, nil)
		assertUnknown()
		r.scope().base.Lock()
		assert.Equal(1, r.scope().base.nodes["2-orphan0"].refs, "should have one ref")
		assert.Equal(1, r.scope().base.nodes["3-orphan1"].refs, "should have one ref")
		r.scope().base.Unlock()
	}()

	// Create referenced scope.
	s2 := GetSubScope(r, "foo2")
	assertUnknown()
	r.scope().base.Lock()
	assert.Equal(1, r.scope().base.nodes["4-foo2"].refs, "should have one ref")
	r.scope().base.Unlock()

	// Create unreferenced scope, with unreferenced child, but with a reporter
	// leaf.
	GetHealthReporter(GetSubScope(GetSubScope(r, "orphan2"), "orphan3"), "bar").OK("")
	r.scope().base.Lock()
	assert.Contains(r.scope().base.nodes, "5-orphan2")
	assert.Contains(r.scope().base.nodes, "6-orphan3")
	r.scope().base.Unlock()

	// Force GC.
	runtime.GC()

	r.scope().base.Lock()
	assert.NotContains(r.scope().base.nodes, "2-this-one-should-be-gone", "should have been removed")
	assert.Contains(r.scope().base.nodes, "4-foo2", "")

	assert.Contains(r.scope().base.nodes, "5-orphan2")
	assert.Contains(r.scope().base.nodes, "6-orphan3")
	r.scope().base.Unlock()

	GetHealthReporter(s2, "bar").OK("")
	assertOK()
}

func TestDuplicateReporters(t *testing.T) {
	assert := assert.New(t)
	hr, assertOK, _, _ := createMockReporter(assert)
	s, done := createRoot(hr)
	defer done()

	fooScope := GetSubScope(s, "foo")
	for i := 0; i < 10; i++ {
		GetHealthReporter(fooScope, "test").OK("")
	}
	assertOK()
	base := fooScope.(*scope).base
	assert.Len(base.nodes, 3, "should have root, foo and just one test")
	assert.Len(base.idToChildren[base.rootID], 1, "root should have only one (foo)")
	GetHealthReporter(fooScope, "test2").OK("")
	assert.Len(base.nodes, 4, "should have root, foo, test, test2")
}

func BenchmarkStructuredReporter(b *testing.B) {
	wg := &sync.WaitGroup{}
	hr, _, _, _ := createMockReporter(nil)
	s, done := createRoot(hr)
	defer done()
	ctx, cancel := context.WithCancel(context.Background())
	// 10^6 reporters
	recurse(ctx, 4, 10, s, wg)
	wg.Wait()
	cancel()
}

var count atomic.Uint32

func recurse(ctx context.Context, d, factor int, s Scope, wg *sync.WaitGroup) {
	type frame struct {
		d, factor int
		s         Scope
	}
	stack := []frame{
		{
			d:      d,
			factor: factor,
			s:      s,
		},
	}
	for len(stack) != 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if s.d == 0 {
			wg.Add(1)
			go func() {
				defer func() {
					wg.Done()
				}()
				hr := GetHealthReporter(s.s, "foo")
				fmt.Println("Starting:", count.Add(1))
				for i := 0; i < 100; i++ {
					select {
					case <-ctx.Done():
						return
					default:
						hr.OK("yay")
					}
				}
			}()
			continue
		} else {
			for i := 0; i < s.factor; i++ {
				stack = append(stack, frame{
					d:      s.d - 1,
					factor: s.factor,
					s:      s.s,
				})
			}
		}
	}
}

type mockReporter struct {
	ok, degraded, stopped func(string)
}

func (s *mockReporter) setStatus(n Update) {
	switch n.Level() {
	case StatusOK:
		s.ok(n.String())
	case StatusDegraded:
		s.degraded(n.String())
	case StatusStopped:
		s.stopped(n.String())
	}
}
