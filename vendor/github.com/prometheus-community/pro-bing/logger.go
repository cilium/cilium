// Copyright The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package probing

import "log"

type Logger interface {
	Fatalf(format string, v ...interface{})
	Errorf(format string, v ...interface{})
	Warnf(format string, v ...interface{})
	Infof(format string, v ...interface{})
	Debugf(format string, v ...interface{})
}

type StdLogger struct {
	Logger *log.Logger
}

func (l StdLogger) Fatalf(format string, v ...interface{}) {
	l.Logger.Printf("FATAL: "+format, v...)
}

func (l StdLogger) Errorf(format string, v ...interface{}) {
	l.Logger.Printf("ERROR: "+format, v...)
}

func (l StdLogger) Warnf(format string, v ...interface{}) {
	l.Logger.Printf("WARN: "+format, v...)
}

func (l StdLogger) Infof(format string, v ...interface{}) {
	l.Logger.Printf("INFO: "+format, v...)
}

func (l StdLogger) Debugf(format string, v ...interface{}) {
	l.Logger.Printf("DEBUG: "+format, v...)
}

type NoopLogger struct {
}

func (l NoopLogger) Fatalf(format string, v ...interface{}) {
}

func (l NoopLogger) Errorf(format string, v ...interface{}) {
}

func (l NoopLogger) Warnf(format string, v ...interface{}) {
}

func (l NoopLogger) Infof(format string, v ...interface{}) {
}

func (l NoopLogger) Debugf(format string, v ...interface{}) {
}
