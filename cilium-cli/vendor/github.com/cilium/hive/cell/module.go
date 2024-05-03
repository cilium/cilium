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
// The id and description will be included in the object dump (hive.PrintObjects).
// The id must be lower-case, at most 30 characters and only contain [a-z0-9-_].
// The description can contain [a-zA-Z0-9_- ] and must be shorter than 80 characters.
//
// As the description will be shown alongside the id, it should not repeat the id, but
// rather expand on it, for example;
//
//	endpoint-manager: Manages and provides access to endpoints
//	^- id             ^- description
//
// Private constructors with a module (ProvidePrivate) are only accessible
// within this module and its sub-modules.
func Module(id, description string, cells ...Cell) Cell {
	validateIDAndDescription(id, description)
	return &module{id, description, cells}
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
// Supplied with [hive.Options] field 'ModuleDecorators'.
//
// This can be used to provide module-specific instances of objects application
// wide, similar to how *slog.Logger is provided by default.
type ModuleDecorator any

type ModuleDecorators []ModuleDecorator

// ModulePrivateProvider is the optional private provide function used for each module
// to provide objects in each module's scope.
// Supplied with [hive.Options] field 'ModulePrivateProviders'.
//
// This is different from a [ModuleDecorator] in that this can be used to provide objects
// that do not yet exist in the object graph, whereas [ModuleDecorator] requires that the
// objects that are being decorated already exist.

type ModulePrivateProvider any

type ModulePrivateProviders []ModulePrivateProvider

var (
	idRegex          = regexp.MustCompile(`^[a-z][a-z0-9_\-]{1,30}$`)
	descriptionRegex = regexp.MustCompile(`^[a-zA-Z0-9_\- ]{1,80}$`)
)

func validateIDAndDescription(id, description string) {
	if !idRegex.MatchString(id) {
		panic(fmt.Sprintf("Invalid hive.Module id: %q, expected to id match %s", id, idRegex))
	}
	if !descriptionRegex.MatchString(description) {
		panic(fmt.Sprintf("Invalid hive.Module description: %q, expected to match regex %q", description, descriptionRegex))
	}
}

type module struct {
	// id is the module identity. It is shown in object output and is used to derive
	// the scoped logger.
	id string

	// description is a human-readable short description for the module. Shown in object output
	// alongside the identifier.
	description string

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

type moduleDecoratorParams struct {
	In
	ModuleDecorators ModuleDecorators
}

func (m *module) moduleDecorators(scope *dig.Scope) error {
	provide := func(p moduleDecoratorParams) error {
		for _, d := range p.ModuleDecorators {
			if err := scope.Decorate(d); err != nil {
				return err
			}
		}
		return nil
	}
	return scope.Invoke(provide)
}

type modulePrivateProviderParams struct {
	In
	ModulePrivateProviders ModulePrivateProviders
}

func (m *module) modulePrivateProviders(scope *dig.Scope) error {
	provide := func(p modulePrivateProviderParams) error {
		for _, d := range p.ModulePrivateProviders {
			if err := scope.Provide(d); err != nil {
				return err
			}
		}
		return nil
	}
	return scope.Invoke(provide)
}

func (m *module) Apply(c container) error {
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

	if err := m.moduleDecorators(scope); err != nil {
		return err
	}

	if err := m.modulePrivateProviders(scope); err != nil {
		return err
	}

	for _, cell := range m.cells {
		if err := cell.Apply(scope); err != nil {
			return err
		}
	}
	return nil
}

func (m *module) Info(c container) Info {
	n := NewInfoNode("Ⓜ️ " + m.id + " (" + m.description + ")")
	for _, cell := range m.cells {
		n.Add(cell.Info(c))
	}
	return n
}
