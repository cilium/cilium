// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"context"
	"fmt"
	"regexp"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestStatusProvider(t *testing.T) {
	assert := assert.New(t)
	sp := NewHealthProvider()
	reporter := sp.forModule("module000")
	reporter.OK("OK")
	reporter.Degraded("bad", fmt.Errorf("zzz"))
	reporter.Stopped("meh")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	assert.NoError(sp.Stop(ctx))
	assert.Equal(sp.processed(), uint64(3))
	assert.Equal(StatusDegraded, sp.Get("module000").Level)
	reporter.OK("")
}

func TestHealthReporter(t *testing.T) {
	m := 200
	u := 200

	assert := assert.New(t)
	s := NewHealthProvider()
	wg := &sync.WaitGroup{}
	for i := 0; i < m; i++ {
		reporter := s.forModule(fmt.Sprintf("module-%d", i))
		wg.Add(1)
		go func(hr HealthReporter) {
			for j := 1; j <= u; j++ {
				if j%2 == 0 {
					hr.OK("yup!")
				} else {
					hr.Degraded("nope", fmt.Errorf("somerr"))
				}
			}
			hr.Stopped("ok we're finished!")
			wg.Done()
		}(reporter)
	}
	wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Hour)
	defer cancel()
	assert.NoError(s.Stop(ctx))
	// note: stopped decl adds 1 more update.
	assert.Equal(m*(u+1), int(s.processed()))

	for _, s := range s.(*healthProvider).moduleStatuses {
		assert.Equal(s.Update.Level, StatusOK)
		assert.True(s.Stopped)
	}
}

func TestStatusString(t *testing.T) {
	assert := assert.New(t)
	s := Status{
		Update: Update{
			Level:    StatusUnknown,
			ModuleID: "m-000",
			Err:      nil,
			Message:  "something happened",
		},
	}
	assert.Equal("Status{ModuleID: m-000, Level: Unknown, Since: never, Message: something happened, Err: <nil>}",
		s.String())

	s.Update.Level = StatusOK
	assert.Equal("Status{ModuleID: m-000, Level: OK, Since: never, Message: something happened, Err: <nil>}",
		s.String())

	s.Update.Err = fmt.Errorf("zzz")
	assert.Equal("Status{ModuleID: m-000, Level: OK, Since: never, Message: something happened, Err: zzz}",
		s.String())

	s.LastUpdated = time.Now()
	assert.Regexp(regexp.MustCompile("^Status.*Since: [0-9.]*[µnm]+s ago,.*$"), s.String())
}
