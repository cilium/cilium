// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/hive/cell"
)

func TestVitalsToModuleHealth(t *testing.T) {
	uu := map[string]struct {
		s cell.Status
		e *models.ModuleHealth
	}{
		"empty": {
			e: &models.ModuleHealth{
				LastOk:      "n/a",
				LastUpdated: "n/a",
			},
		},
		"happy": {
			s: cell.Status{
				Update: cell.Update{
					FullModuleID: []string{"fred"},
					Message:      "blee",
					Err:          fmt.Errorf("zorg"),
				},
				Stopped: true,
				Final:   "fred",
			},
			e: &models.ModuleHealth{
				Message:     "blee",
				ModuleID:    "fred",
				LastOk:      "n/a",
				LastUpdated: "n/a",
			},
		},
	}

	for k := range uu {
		u := uu[k]
		assert.Equal(t, u.e, toModuleHealth(u.s))
	}
}

func TestVitalsToAgeHuman(t *testing.T) {
	uu := map[string]struct {
		t time.Time
		e string
	}{
		"zero": {
			e: "n/a",
		},
	}

	for k := range uu {
		u := uu[k]
		assert.Equal(t, u.e, toAgeHuman(u.t))
	}
}
