// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package log provides a central logging package that wraps MetalLB's logging.
package log

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/option"
)

// Log logs messages from the MetalLB code. The messages are noisy and
// therefore only logged when Cilium is running with debug enabled.
func (l *Logger) Log(args ...interface{}) error {
	// Bypass the code below if we aren't going to log anyway.
	if !option.Config.Debug {
		return nil
	}

	b := strings.Builder{}
	for _, a := range args {
		switch t := a.(type) {
		case string:
			b.WriteString(t)
			b.WriteString(" ")
		case error:
			b.WriteString(t.Error())
			b.WriteString(" ")
		case fmt.Stringer:
			b.WriteString(t.String())
			b.WriteString(" ")
		}
	}
	l.Debug(strings.TrimSpace(b.String()))
	return nil
}

// Logger wraps the logrus package so that it can conform to the Logger from
// MetalLB.
type Logger struct {
	*logrus.Entry
}
