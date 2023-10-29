// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
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
				Level:       "Unknown",
			},
			s: cell.Status{},
		},
		"happy": {
			s: cell.Status{
				FullModuleID: cell.FullModuleID{"fred"},
				Update:       mockUpdate{"blee", cell.StatusOK},
				Stopped:      true,
			},
			e: &models.ModuleHealth{
				Message:     "blee",
				ModuleID:    "fred",
				LastOk:      "n/a",
				LastUpdated: "n/a",
				Level:       "OK",
			},
		},
	}

	for k := range uu {
		u := uu[k]
		mh, err := toModuleHealth(u.s)
		assert.NoError(t, err)
		assert.Equal(t, u.e, mh)
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

type mockUpdate struct {
	msg   string
	level cell.Level
}

func (m mockUpdate) Level() cell.Level {
	return m.level
}
func (m mockUpdate) String() string {
	return "blee"
}
func (m mockUpdate) JSON() ([]byte, error) {
	return []byte(m.msg), nil
}
func (m mockUpdate) Timestamp() time.Time {
	return time.Time{}
}
