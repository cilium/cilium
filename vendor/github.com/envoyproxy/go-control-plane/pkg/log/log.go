// Copyright 2020 Envoyproxy Authors
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.

// Package log provides a logging interface for use in this library.
package log

// Logger interface for reporting informational and warning messages.
type Logger interface {
	// Debugf logs a formatted debugging message.
	Debugf(format string, args ...interface{})

	// Infof logs a formatted informational message.
	Infof(format string, args ...interface{})

	// Warnf logs a formatted warning message.
	Warnf(format string, args ...interface{})

	// Errorf logs a formatted error message.
	Errorf(format string, args ...interface{})
}

// LoggerFuncs implements the Logger interface, allowing the
// caller to specify only the logging functions that are desired.
type LoggerFuncs struct {
	DebugFunc func(string, ...interface{})
	InfoFunc  func(string, ...interface{})
	WarnFunc  func(string, ...interface{})
	ErrorFunc func(string, ...interface{})
}

// Debugf logs a formatted debugging message.
func (f LoggerFuncs) Debugf(format string, args ...interface{}) {
	if f.DebugFunc != nil {
		f.DebugFunc(format, args...)
	}
}

// Infof logs a formatted informational message.
func (f LoggerFuncs) Infof(format string, args ...interface{}) {
	if f.InfoFunc != nil {
		f.InfoFunc(format, args...)
	}
}

// Warnf logs a formatted warning message.
func (f LoggerFuncs) Warnf(format string, args ...interface{}) {
	if f.WarnFunc != nil {
		f.WarnFunc(format, args...)
	}
}

// Errorf logs a formatted error message.
func (f LoggerFuncs) Errorf(format string, args ...interface{}) {
	if f.ErrorFunc != nil {
		f.ErrorFunc(format, args...)
	}
}
