package scoped

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestScopedReporter(t *testing.T) {
	// TODO: We need to be able to clean up reporters when they
	// "out-of-scope".
	assert := assert.New(t)
	hr := &mockReporter{}
	assertDegraded := func() {
		assert.Eventually(func() bool {
			return hr.isDegraded()
		}, time.Millisecond*50, time.Millisecond*10)
	}
	assertOk := func() {
		assert.Eventually(func() bool {
			return !hr.isDegraded()
		}, time.Millisecond*50, time.Millisecond*10)
	}
	r := WithLabels(context.TODO(), hr, Labels{"name": "root"})
	c1 := WithLabels(context.TODO(), r, Labels{"name": "child1"})
	ctx, cancel := context.WithCancel(context.Background())
	c2 := WithLabels(ctx, r, Labels{"name": "child2"})
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

	//c2.OK("o2")
	//assert.False(hr.isDegraded())

	//assert.False(hr.isDegraded())
	// Should these even report?
	//r.Degraded("???", fmt.Errorf("root degraded"))
	//r.OK("root is ok")
}

type mockReporter struct {
	ok bool
}

func (m *mockReporter) isDegraded() bool {
	return !m.ok
}

func (m *mockReporter) OK(message string) {
	fmt.Println("# OK:", message)
	m.ok = true
}

func (m *mockReporter) Degraded(message string, err error) {
	fmt.Println("# Degraded:", message, err)
	m.ok = false
}

func (m *mockReporter) Stopped(message string) {
	panic("implement me")
}
