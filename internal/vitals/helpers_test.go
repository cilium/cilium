// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vitals_test

import (
	"testing"

	"github.com/cilium/cilium/internal/vitals"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/gookit/color"
	"github.com/stretchr/testify/assert"
)

func TestScoreIcon(t *testing.T) {
	uu := map[string]struct {
		l cell.Level
		e string
	}{
		"ok": {
			l: cell.LevelOK,
			e: "✅",
		},
		"degraded": {
			l: cell.LevelDegraded,
			e: "❌",
		},
		"down": {
			l: cell.LevelDown,
			e: "🙀",
		},
		"unknown": {
			l: cell.Level("blee"),
			e: "🚧",
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, vitals.ScoreIcon(u.l))
		})
	}
}

func TestHealthScoreColor(t *testing.T) {
	uu := map[string]struct {
		s vitals.HealthScore
		e *color.Style256
	}{
		"low": {
			s: vitals.Low,
			e: vitals.ErrColor,
		},
		"medium": {
			s: vitals.Medium,
			e: vitals.WarnColor,
		},
		"high": {
			s: vitals.High,
			e: vitals.OkColor,
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, vitals.HealthScoreColor(u.s))
		})
	}
}

func TestLevelColor(t *testing.T) {
	uu := map[string]struct {
		l cell.Level
		e *color.Style256
	}{
		"ok": {
			l: cell.LevelOK,
			e: vitals.OkColor,
		},
		"down": {
			l: cell.LevelDown,
			e: vitals.WarnColor,
		},
		"degraded": {
			l: cell.LevelDegraded,
			e: vitals.ErrColor,
		},
		"unknown": {
			l: cell.Level("blee"),
			e: vitals.NoptColor,
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, vitals.LevelColor(u.l))
		})
	}
}
