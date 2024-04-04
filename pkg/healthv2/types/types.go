// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"fmt"
	"strings"
	"time"
)

// ModuleID is the module identifier. Provided in the module's scope.
type ModuleID string

// FullModuleID is the fully qualified module identifier, e.g. the
// concat of nested module ids, e.g. "agent.controlplane.endpoint-manager".
// Provided in the module's scope.
type FullModuleID []string

func (i FullModuleID) String() string {
	return strings.Join(i, ".")
}

// Provider has functionality to create health reporters, scoped a
// module.
type Provider interface {
	ForModule(mid FullModuleID) Health
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
	Module    FullModuleID
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

// Status represents a current health status update.
type Status struct {
	ID      Identifier
	Level   Level
	Message string
	Error   error
	LastOK  time.Time
	Updated time.Time
	Stopped time.Time
	// Final is the final message set when a status is stopped.
	Final string
	Count uint64
}

func (Status) TableHeader() []string {
	return []string{"Module", "Component", "Level", "Message", "LastOK", "UpdatedAt", "Count"}
}

func (s Status) TableRow() []string {
	return []string{s.ID.Module.String(), s.ID.Component.String(), string(s.Level), s.Message, s.LastOK.Format(time.RFC3339),
		s.Updated.Format(time.RFC3339), fmt.Sprintf("%d", s.Count)}
}

func (s Status) String() string {
	return fmt.Sprintf("%s: [%s] %s", s.ID.String(), s.Level, s.Message)
}

type Level string

const (
	LevelOK       = "OK"
	LevelDegraded = "Degraded"
	LevelStopped  = "Stopped"
)
