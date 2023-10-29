// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package client_test

import (
	"bytes"
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
			e: "Modules Health:\n" +
				"  m1 OK status nominal 2s ago (x0)\n" +
				"  m2 Degraded doh 20s ago (x0)",
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
	t := time.Now().Add(-1 * time.Second * 2).Format(time.RFC3339)
	t2 := time.Now().Add(-1 * time.Second * 20).Format(time.RFC3339)
	return &daemon.GetHealthOK{
		Payload: &models.ModulesHealth{
			Modules: []*models.ModuleHealth{
				{
					ModuleID:    "m1",
					Level:       string(cell.StatusOK),
					Message:     fmt.Sprintf("{\"name\": \"m1\", \"level\":\"OK\",\"message\":\"status nominal\", \"timestamp\": %q}", t),
					LastOk:      "3s",
					LastUpdated: "2s",
				},
				{
					ModuleID:    "m2",
					Level:       string(cell.StatusDegraded),
					Message:     fmt.Sprintf("{\"name\": \"m2\", \"level\":\"Degraded\",\"message\":\"doh\", \"timestamp\": %q}", t2),
					LastOk:      "5m30s",
					LastUpdated: "20s",
				},
			},
		},
	}, nil
}
