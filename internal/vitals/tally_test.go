// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vitals_test

import (
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/internal/vitals"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/stretchr/testify/assert"
)

func TestTallyScore(t *testing.T) {
	uu := map[string]struct {
		t vitals.Tally
		e vitals.HealthScore
	}{
		"ok": {
			t: vitals.Tally{10, 0, 0},
			e: vitals.High,
		},
		"degraded": {
			t: vitals.Tally{10, 0, 1},
			e: vitals.Low,
		},
		"down": {
			t: vitals.Tally{10, 1, 0},
			e: vitals.Medium,
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.t.Score())
		})
	}
}

func TestNewTally(t *testing.T) {
	uu := map[string]struct {
		h models.ModulesHealth
		e vitals.Tally
	}{
		"all": {
			h: models.ModulesHealth{
				Modules: []*models.ModuleHealth{
					{
						Level: string(cell.LevelOK),
					},
					{
						Level: string(cell.LevelDegraded),
					},
					{
						Level: string(cell.LevelDown),
					},
				},
			},
			e: vitals.Tally{1, 1, 1},
		},
		"ok": {
			h: models.ModulesHealth{
				Modules: []*models.ModuleHealth{
					{
						Level: string(cell.LevelOK),
					},
					{
						Level: string(cell.LevelOK),
					},
					{
						Level: string(cell.LevelOK),
					},
				},
			},
			e: vitals.Tally{3, 0, 0},
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, vitals.NewTally(&u.h))
		})
	}
}

func TestTallyCompound(t *testing.T) {
	uu := map[string]struct {
		t1, t2 vitals.Tally
		e      vitals.Tally
	}{
		"empty": {},
		"blank": {
			t1: vitals.Tally{10, 5, 4},
			e:  vitals.Tally{10, 5, 4},
		},
		"normal": {
			t1: vitals.Tally{10, 5, 4},
			t2: vitals.Tally{10, 3, 2},
			e:  vitals.Tally{20, 8, 6},
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, u.t1.Compound(u.t2))
		})
	}
}
