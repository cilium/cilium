// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/hive/cell"
)

// Provider has functionality to create health reporters, scoped a
// module.
type Provider interface {
	ForModule(mid cell.FullModuleID) cell.Health
}

type pathIdent []string

func (p pathIdent) String() string {
	if len(p) == 0 {
		return ""
	}
	return strings.Join(p, ".")
}

// HealthID is used as the key for the primary index for health status
// tables.
type HealthID string

// Identifier is a fully qualified, path based identifier for health status
// which is made up of module ID and component ID parts.
type Identifier struct {
	Module    cell.FullModuleID
	Component pathIdent
}

// WithSubComponent returns view of an identifier with an appended
// subcomponent.
func (i Identifier) WithSubComponent(name string) Identifier {
	return Identifier{
		Module:    i.Module,
		Component: append(i.Component, name),
	}
}

func (i Identifier) String() string {
	return strings.Join([]string{i.Module.String(), i.Component.String()}, ".")
}

func (i Identifier) HealthID() HealthID {
	return HealthID(i.String())
}

// Status represents a current health status update.
type Status struct {
	ID      Identifier
	Level   Level
	Message string
	Error   string
	LastOK  time.Time
	Updated time.Time
	Stopped time.Time
	// Final is the final message set when a status is stopped.
	Final string
	Count uint64
}

func (Status) TableHeader() []string {
	return []string{"Module", "Component", "Level", "Message", "Error", "LastOK", "UpdatedAt", "Count"}
}

func (s Status) TableRow() []string {
	return []string{
		s.ID.Module.String(),
		s.ID.Component.String(),
		string(s.Level),
		s.Message,
		s.Error,
		s.LastOK.Format(time.RFC3339),
		s.Updated.Format(time.RFC3339),
		strconv.FormatUint(s.Count, 10),
	}
}

func (s Status) String() string {
	if s.Error != "" {
		return fmt.Sprintf("%s: [%s] %s: %s", s.ID.String(), s.Level, s.Message, s.Error)
	} else {
		return fmt.Sprintf("%s: [%s] %s", s.ID.String(), s.Level, s.Message)
	}
}

type Level string

const (
	LevelOK       = "OK"
	LevelDegraded = "Degraded"
	LevelStopped  = "Stopped"
)
