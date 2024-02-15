// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"go.uber.org/dig"
)

// Module creates a scoped set of cells with a given identifier.
//
// The id and title will be included in the object dump (hive.PrintObjects).
// The id must be lower-case, at most 30 characters and only contain [a-z0-9-_].
// Title can contain [a-zA-Z0-9_- ] and must be shorter than 80 characters.
//
// Private constructors with a module (ProvidePrivate) are only accessible
// within this module and its sub-modules.
func Module(id, title string, cells ...Cell) Cell {
	validateIDAndTitle(id, title)
	return &module{id, title, cells}
}

// ModuleID is the module identifier. Provided in the module's scope.
type ModuleID string

// FullModuleID is the fully qualified module identifier, e.g. the
// concat of nested module ids, e.g. "agent.controlplane.endpoint-manager".
// Provided in the module's scope.
type FullModuleID []string

func (f FullModuleID) String() string {
	return strings.Join(f, ".")
}

func (f FullModuleID) append(m ModuleID) FullModuleID {
	return append(slices.Clone(f), string(m))
}

// RootLogger is the unscoped logger without any attrs added to it.
type RootLogger *slog.Logger

// ModuleDecorator is the optional decorator function used for each module
// to provide or replace objects in each module's scope.
// Supplied with [hive.Options] field 'ModuleDecorator'.
//
// This can be used to provide module-specific instances of objects application
// wide, similar to how *slog.Logger is provided by default.
type ModuleDecorator any

var (
	idRegex    = regexp.MustCompile(`^[a-z][a-z0-9_\-]{1,30}$`)
	titleRegex = regexp.MustCompile(`^[a-zA-Z0-9_\- ]{1,80}$`)
)

func validateIDAndTitle(id, title string) {
	if !idRegex.MatchString(id) {
		panic(fmt.Sprintf("Invalid hive.Module id: %q, expected to id match %s", id, idRegex))
	}
	if !titleRegex.MatchString(title) {
		panic(fmt.Sprintf("Invalid hive.Module title: %q, expected to title match %s", title, titleRegex))
	}
}

type module struct {
	// id is the module identity. It is shown in object output and is used to derive
	// the scoped logger.
	id string

	// title is a human-readable short title for the module. Shown in object output
	// alongside the identifier.
	title string

	cells []Cell
}

func (m *module) logger(moduleID FullModuleID, rootLog RootLogger) *slog.Logger {
	return (*slog.Logger)(rootLog).With("module", moduleID.String())
}

func (m *module) moduleID() ModuleID {
	return ModuleID(m.id)
}

func (m *module) fullModuleID(parent FullModuleID) FullModuleID {
	return parent.append(m.moduleID())
}

func (m *module) lifecycle(lc Lifecycle, fullID FullModuleID) Lifecycle {
	switch lc := lc.(type) {
	case *DefaultLifecycle:
		return &augmentedLifecycle{
			lc,
			fullID,
		}
	case *augmentedLifecycle:
		return &augmentedLifecycle{
			lc.DefaultLifecycle,
			fullID,
		}
	default:
		return lc
	}
}

type moduleProviderParams struct {
	In
	ModuleDecorator ModuleDecorator `optional:"true"`
}

func (m *module) moduleDecorator(scope *dig.Scope) error {
	provide := func(p moduleProviderParams) error {
		if p.ModuleDecorator != nil {
			return scope.Decorate(p.ModuleDecorator)
		}
		return nil
	}
	if err := scope.Invoke(provide); err != nil {
		return err
	}
	return nil
}

func (m *module) Apply(log *slog.Logger, c container) error {
	scope := c.Scope(m.id)

	// Provide ModuleID and FullModuleID in the module's scope.
	if err := scope.Provide(m.moduleID); err != nil {
		return err
	}
	if err := scope.Decorate(m.fullModuleID); err != nil {
		return err
	}

	if err := scope.Decorate(m.lifecycle); err != nil {
		return err
	}

	if err := scope.Decorate(m.logger); err != nil {
		return err
	}

	if err := m.moduleDecorator(scope); err != nil {
		return err
	}

	for _, cell := range m.cells {
		if err := cell.Apply(log, scope); err != nil {
			return err
		}
	}
	return nil
}

func (m *module) Info(c container) Info {
	n := NewInfoNode("Ⓜ️ " + m.id + " (" + m.title + ")")
	for _, cell := range m.cells {
		n.Add(cell.Info(c))
	}
	return n
}
