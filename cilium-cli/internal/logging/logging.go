// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	cfsslLog "github.com/cloudflare/cfssl/log"
)

func init() {
	cfsslLog.SetLogger(&noopLogger{})
}

// noopLogger implements cfsslLog.SyslogWriter to avoid logging unwanted log messages.
type noopLogger struct{}

// Debug implements cfsslLog.SyslogWriter.
func (s *noopLogger) Debug(msg string) {}

// Info implements cfsslLog.SyslogWriter.
func (s *noopLogger) Info(msg string) {}

// Warning implements cfsslLog.SyslogWriter.
func (s *noopLogger) Warning(msg string) {}

// Error implements cfsslLog.SyslogWriter.
func (s *noopLogger) Err(msg string) {}

// Crit implements cfsslLog.SyslogWriter.
func (s *noopLogger) Crit(msg string) {}

// Emerg implements cfsslLog.SyslogWriter.
func (s *noopLogger) Emerg(msg string) {}
