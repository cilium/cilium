// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"fmt"
	"regexp"

	"github.com/sirupsen/logrus"

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

func (m *module) Apply(c container) error {
	scope := c.Scope(m.id)

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
