package cell

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func createMock(assert *assert.Assertions) (assertDegraded func(), assertOk func(), hr *mockReporter) {
	hr = &mockReporter{}
	assertDegraded = func() {
		assert.Eventually(func() bool {
			return hr.isDegraded()
		}, time.Millisecond*50, time.Millisecond*10)
	}
	assertOk = func() {
		assert.Eventually(func() bool {
			return !hr.isDegraded()
		}, time.Millisecond*50, time.Millisecond*10)
	}
	return
}

func TestScopedReporter(t *testing.T) {
	// TODO: We need to be able to clean up reporters when they
	// "out-of-scope".
	assertDegraded, assertOk, hr := createMock(assert.New(t))
	r := withLabels(context.TODO(), hr, Labels{"name": "root"})
	c1 := withLabels(context.TODO(), r, Labels{"name": "child1"})
	ctx, cancel := context.WithCancel(context.Background())
	c2 := withLabels(ctx, r, Labels{"name": "child2"})
	c2.Degraded("d0", nil)
	assertDegraded()
	c1.OK("o1")
	assertDegraded()
	c2.OK("o2")
	assertOk()
	c2.Degraded("d1", nil)
	assertDegraded()
	cancel()
	assertOk()
}
func TestScopedReporter2(t *testing.T) {
	assertDegraded, assertOk, hr := createMock(assert.New(t))
	r := withLabels(context.TODO(), hr, Labels{"name": "root"})
	c1 := withLabels(context.TODO(), r, Labels{"name": "root.1"})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c2 := withLabels(ctx, r, Labels{"name": "root.2"})
	cc2 := withLabels(ctx, c2, Labels{"name": "root.2.1"})
	cc2.OK("o0")
	assertOk()
	cc2.Degraded("d0", nil)
	assertDegraded()
	c1.Degraded("d1", nil)
	c1.OK("o1")
	assertDegraded()
	cc2.OK("o2")
	assertOk()
}

func TestRender(t *testing.T) {
	assert := assert.New(t)
	_, _, hr := createMock(assert)
	r := withLabels(context.TODO(), hr, Labels{
		"name": "endpoint-manager",
	})
	w := &strings.Builder{}
	c1 := withLabels(context.TODO(), r, Labels{"name": "endpoint-0"})
	c1.OK("o1")
	c2 := withLabels(context.TODO(), r, Labels{"name": "endpoint-1"})
	c2.OK("o2")
	cc2 := withLabels(context.TODO(), c2, Labels{"name": "k8s-sync"})
	cc2.Degraded("d0", nil)
	r.render(2, w)
	fmt.Println(w.String())
}

type mockReporter struct {
	ok bool
}

func (m *mockReporter) isDegraded() bool {
	return !m.ok
}

func (m *mockReporter) OK(message string) {
	m.ok = true
}

func (m *mockReporter) Degraded(message string, err error) {
	m.ok = false
}

func (m *mockReporter) Stopped(message string) {
	panic("implement me")
}
