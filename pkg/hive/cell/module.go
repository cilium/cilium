// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/sirupsen/logrus"
	"go.uber.org/dig"

	healthv2Types "github.com/cilium/cilium/pkg/healthv2/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

func (m *module) logger(log logrus.FieldLogger) logrus.FieldLogger {
	return log.WithField(logfields.LogSubsys, m.id)
}

func (m *module) moduleID() ModuleID {
	return ModuleID(m.id)
}

func (m *module) fullModuleID(parent FullModuleID) FullModuleID {
	return parent.append(m.moduleID())
}

type wipHealthV2Shim struct {
	healthv2Types.Health
}

func (h *wipHealthV2Shim) Name() string {
	return ""
}

func (h *wipHealthV2Shim) Close() {
	if h.Health == nil {
		return
	}
	h.Health.Close()
}

func (h *wipHealthV2Shim) Realize() {}

func (h *wipHealthV2Shim) scope() *subReporter { return nil }

type noOpReporter struct{}

func (n noOpReporter) OK(_ string)                            {}
func (n noOpReporter) Close()                                 {}
func (n noOpReporter) Stopped(_ string)                       {}
func (n noOpReporter) Degraded(_ string, _ error)             {}
func (n noOpReporter) NewScope(_ string) healthv2Types.Health { return noOpReporter{} }

var _ HealthReporter = &wipHealthV2Shim{}

type ScopeParams struct {
	In
	Provider healthv2Types.Provider `optional:"true"`
}

// This is a temporary solution, eventually this will be replaced by the external hive module hooks
// to avoid internal coupling...
func createStructedScope(id FullModuleID, params ScopeParams, lc Lifecycle) (healthv2Types.Health, Scope) {
	if params.Provider == nil {
		return nil, &wipHealthV2Shim{}
	}
	rs := params.Provider.ForModule(healthv2Types.FullModuleID(id))
	return rs, &wipHealthV2Shim{rs}
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

func (m *module) Apply(c container) error {
	scope := c.Scope(m.id)

	// Provide ModuleID and FullModuleID in the module's scope.
	if err := scope.Provide(m.moduleID); err != nil {
		return err
	}
	if err := scope.Decorate(m.fullModuleID); err != nil {
		return err
	}

	// Provide module scoped status reporter, used for reporting module level
	// health status.
	if err := scope.Provide(createStructedScope, dig.Export(false)); err != nil {
		return err
	}

	if err := scope.Decorate(m.lifecycle); err != nil {
		return err
	}

	if err := scope.Decorate(m.logger); err != nil {
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
	n := NewInfoNode("Ⓜ️ " + m.id + " (" + m.title + ")")
	for _, cell := range m.cells {
		n.Add(cell.Info(c))
	}
	return n
}
