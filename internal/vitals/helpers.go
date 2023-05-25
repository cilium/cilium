// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vitals

import (
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/gookit/color"
)

var (
	OkColor   = color.S256(118)
	WarnColor = color.S256(214)
	ErrColor  = color.S256(196)
	NoptColor = color.S256(246)
	MsgColor  = color.S256(246)
)

// ScoreIcon returns an icon based on module health.
func ScoreIcon(l cell.Level) string {
	switch l {
	case cell.LevelDegraded:
		return "❌"
	case cell.LevelDown:
		return "🙀"
	case cell.LevelOK:
		return "✅"
	default:
		return "🚧"
	}
}

// HealthScoreColor returns overall health score color.
func HealthScoreColor(s HealthScore) *color.Style256 {
	switch s {
	case Low:
		return ErrColor
	case Medium:
		return WarnColor
	default:
		return OkColor
	}
}

// LevelColor returns corresponding module health level color.
func LevelColor(l cell.Level) *color.Style256 {
	switch l {
	case cell.LevelDegraded:
		return ErrColor
	case cell.LevelDown:
		return WarnColor
	case cell.LevelOK:
		return OkColor
	default:
		return NoptColor
	}
}
