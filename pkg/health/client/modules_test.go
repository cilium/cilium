// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/health/client"
	"github.com/cilium/cilium/pkg/hive/cell"
)

func TestGetAndFormatModulesHealth(t *testing.T) {
	uu := map[string]struct {
		h client.ModulesHealth
		e string
		v bool
	}{
		"empty": {
			h: newTestMHEmpty(),
			e: "Modules Health:\tno health payload detected",
		},
		"happy": {
			h: newTestMHappy(),
			e: "Modules Health:\tStopped(0) Degraded(1) OK(1) Unknown(0)",
		},
		"happy-verbose": {
			h: newTestMHappy(),
			e: `Modules Health:
agent
├── m1                                                      [OK] status nominal (2s, x0)
└── a
    └── b
        └── c
            ├── fred                                        [OK] yo (20s, x1)
            │   └── blee                                    [OK] doh (20s, x1)
            └── dork                                        [DEGRADED] bozo -- BOOM! (20s, x1)`,
			v: true,
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			w := bytes.NewBufferString("")
			client.GetAndFormatModulesHealth(w, u.h, u.v)
			assert.Equal(t, u.e, strings.TrimSpace(w.String()))
		})
	}
}

// Helpers

type testMHEmpty struct{}

func newTestMHEmpty() *testMHEmpty {
	return &testMHEmpty{}
}

func (m *testMHEmpty) GetHealth(params *daemon.GetHealthParams, opts ...daemon.ClientOption) (*daemon.GetHealthOK, error) {
	return &daemon.GetHealthOK{}, nil
}

type testMHappy struct{}

func newTestMHappy() *testMHappy {
	return &testMHappy{}
}

func (m *testMHappy) GetHealth(params *daemon.GetHealthParams, opts ...daemon.ClientOption) (*daemon.GetHealthOK, error) {
	t1, t2 := time.Now().Add(-1*time.Second*2), time.Now().Add(-1*time.Second*20)
	return &daemon.GetHealthOK{
		Payload: &models.ModulesHealth{
			Modules: []*models.ModuleHealth{
				{
					ModuleID:    "m1",
					Level:       string(cell.StatusOK),
					Message:     makeSimpleMsg(t1),
					LastOk:      "3s",
					LastUpdated: "2s",
				},
				{
					ModuleID:    "a.b.c",
					Level:       string(cell.StatusDegraded),
					Message:     makeComplexMsg(t2),
					LastOk:      "5m30s",
					LastUpdated: "20s",
				},
			},
		},
	}, nil
}

func makeSimpleMsg(t time.Time) string {
	s := cell.StatusNode{
		Name:            "m1",
		LastLevel:       cell.StatusOK,
		UpdateTimestamp: t,
		Message:         "status nominal",
	}

	bb, _ := json.Marshal(s)
	return string(bb)
}

func makeComplexMsg(t time.Time) string {
	s := cell.StatusNode{
		Name:      "a.b.c",
		LastLevel: cell.StatusOK,
		Count:     1,
		SubStatuses: []*cell.StatusNode{
			{
				Name:      "fred",
				LastLevel: cell.StatusOK,
				Count:     1,
				SubStatuses: []*cell.StatusNode{
					{
						Name:            "blee",
						LastLevel:       cell.StatusOK,
						Message:         "doh",
						UpdateTimestamp: t,
						Count:           1,
					},
					{
						Name:            "fred",
						LastLevel:       cell.StatusOK,
						Message:         "yo",
						UpdateTimestamp: t,
						Count:           1,
					},
				},
			},
			{
				Name:            "dork",
				LastLevel:       cell.StatusDegraded,
				Message:         "bozo",
				Count:           1,
				Error:           fmt.Errorf("BOOM!").Error(),
				UpdateTimestamp: t,
			},
		},
	}

	bb, _ := json.Marshal(s)
	return string(bb)
}
