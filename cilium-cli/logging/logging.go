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
func (s *noopLogger) Debug(_ string) {}

// Info implements cfsslLog.SyslogWriter.
func (s *noopLogger) Info(_ string) {}

// Warning implements cfsslLog.SyslogWriter.
func (s *noopLogger) Warning(_ string) {}

// Error implements cfsslLog.SyslogWriter.
func (s *noopLogger) Err(_ string) {}

// Crit implements cfsslLog.SyslogWriter.
func (s *noopLogger) Crit(_ string) {}

// Emerg implements cfsslLog.SyslogWriter.
func (s *noopLogger) Emerg(_ string) {}
