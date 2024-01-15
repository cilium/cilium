// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb"
	"github.com/stretchr/testify/assert"
)

// Goals:
// * Simplicity
// * Data schema
// * Testing store
// * Hubble integration

func TestLoop(t *testing.T) {
	h := hive.New(
		statedb.Cell,
		cell.Invoke(func(pp healthProviderParams, sh hive.Shutdowner) error {
			defer sh.Shutdown()
			hp, err := NewHealthProvider(pp)
			if err != nil {
				return err
			}
			hp.Start(context.Background())
			mid := cell.FullModuleID([]string{"foo", "bar"})
			m, err := hp.forModule(mid)
			assert.NoError(t, err)
			r := rootScope(mid, m)
			go func() {
				for {
					GetHealthReporter(r, "comp0").OK("all good")
					GetHealthReporter(r, "comp02").OK("all good")
					s := GetSubScope(r, "comp1")
					GetHealthReporter(s, "leaf").OK("all good")
					time.Sleep(1 * time.Second)
				}
			}()
			time.Sleep(3 * time.Second)
			hp.Stop(context.Background())
			fmt.Println(hp.All())
			tx := hp.(*healthProvider).db.ReadTxn()
			iter, _ := hp.(*healthProvider).statusTable.All(tx)
			for {
				o, _, ok := iter.Next()
				if !ok {
					break
				}
				fmt.Println("s:", o)
			}
			return nil
		}),
	)
	assert.NoError(t, h.Run())
}

// func TestStatusProvider(t *testing.T) {
// 	assert := assert.New(t)
// 	sp := NewHealthProvider()
// 	mid := FullModuleID{"module000"}
// 	reporter := GetHealthReporter(TestScopeFromProvider(mid, sp), "foo")

// 	reporter.OK("OK")
// 	var err error
// 	var s Status
// 	assertStatus := func(l Level) {
// 		assert.Eventually(func() bool {
// 			s, err = sp.Get(mid)
// 			return err == nil && s.Level() == l
// 		}, time.Second, time.Millisecond*50)
// 	}
// 	assertStatus(StatusOK)
// 	reporter.Degraded("degraded", nil)
// 	assertStatus(StatusDegraded)
// 	reporter.OK("-")
// 	assertStatus(StatusOK)
// 	reporter.Stopped("done")
// 	assertStatus(StatusOK)
// }

// func TestHealthReporter(t *testing.T) {
// 	m := 200
// 	u := 200

// 	assert := assert.New(t)
// 	s := NewHealthProvider()
// 	wg := &sync.WaitGroup{}
// 	for i := 0; i < m; i++ {
// 		reporter := s.forModule([]string{fmt.Sprintf("module-%d", i)})
// 		wg.Add(1)
// 		go func(hr statusNodeReporter) {
// 			for j := 1; j <= u; j++ {
// 				if j%2 == 0 {
// 					hr.setStatus(&StatusNode{LastLevel: StatusOK})
// 				} else {
// 					hr.setStatus(&StatusNode{LastLevel: StatusDegraded})
// 				}
// 			}
// 			wg.Done()
// 		}(reporter)
// 	}
// 	wg.Wait()
// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Hour)
// 	defer cancel()
// 	assert.NoError(s.Stop(ctx))
// 	assert.Equal(m*u, int(s.processed()))

// 	for _, s := range s.(*healthProvider).moduleStatuses {
// 		assert.Equal(StatusOK, s.Update.Level())
// 	}
// }

// func TestStatusString(t *testing.T) {
// 	assert := assert.New(t)
// 	un := &StatusNode{
// 		LastLevel: StatusOK,
// 		Message:   "something happened",
// 	}
// 	s := Status{
// 		Update:       un,
// 		FullModuleID: FullModuleID{"m-000"},
// 	}
// 	assert.Equal("Status{ModuleID: m-000, Level: OK, Since: never, Message: something happened}",
// 		s.String())
// }
