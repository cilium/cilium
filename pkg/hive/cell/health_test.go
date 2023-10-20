// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStatusProvider(t *testing.T) {
	assert := assert.New(t)
	sp := NewHealthProvider()
	mid := FullModuleID{"module000"}
	reporter := GetHealthReporter(TestScopeFromProvider(mid, sp), "foo")

	reporter.OK("OK")
	var err error
	var s Status
	assertStatus := func(l Level) {
		assert.Eventually(func() bool {
			s, err = sp.Get(mid)
			return err == nil && s.Level() == l
		}, time.Second, time.Millisecond*50)
	}
	assertStatus(StatusOK)
	reporter.Degraded("degraded", nil)
	assertStatus(StatusDegraded)
	reporter.OK("-")
	assertStatus(StatusOK)
	reporter.Stopped("done")
	assertStatus(StatusOK)
}

func TestHealthReporter(t *testing.T) {
	m := 200
	u := 200

	assert := assert.New(t)
	s := NewHealthProvider()
	wg := &sync.WaitGroup{}
	for i := 0; i < m; i++ {
		reporter := s.forModule([]string{fmt.Sprintf("module-%d", i)})
		wg.Add(1)
		go func(hr statusNodeReporter) {
			for j := 1; j <= u; j++ {
				if j%2 == 0 {
					hr.setStatus(&StatusNode{LastLevel: StatusOK})
				} else {
					hr.setStatus(&StatusNode{LastLevel: StatusDegraded})
				}
			}
			wg.Done()
		}(reporter)
	}
	wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Hour)
	defer cancel()
	assert.NoError(s.Stop(ctx))
	assert.Equal(m*u, int(s.processed()))

	for _, s := range s.(*healthProvider).moduleStatuses {
		assert.Equal(StatusOK, s.Update.Level())
	}
}

func TestStatusString(t *testing.T) {
	assert := assert.New(t)
	un := &StatusNode{
		LastLevel: StatusOK,
		Message:   "something happened",
	}
	s := Status{
		Update:       un,
		FullModuleID: FullModuleID{"m-000"},
	}
	assert.Equal("Status{ModuleID: m-000, Level: OK, Since: never, Message: something happened}",
		s.String())
}
