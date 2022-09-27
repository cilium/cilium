// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cell

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Module creates a named set of cells.
// The name will be included in the object dump (hive.PrintObjects) and
// in the dot graph (hive.PrintDotGraph).
func Module(name string, cells ...Cell) Cell {
	return &module{name, cells}
}

// module is a named set of cells.
type module struct {
	name  string
	cells []Cell
}

func (m *module) logger(log logrus.FieldLogger) logrus.FieldLogger {
	return log.WithField(logfields.LogSubsys, m.name)
}

func (m *module) Apply(c container) error {
	scope := c.Scope(m.name)

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

func (m *module) Info() Info {
	n := NewInfoNode("Ⓜ️ " + m.name)
	for _, cell := range m.cells {
		n.Add(cell.Info())
		n.AddBreak()
	}
	return n
}
