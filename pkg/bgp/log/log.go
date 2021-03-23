// Copyright 2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package log provides a central logging package that wraps MetalLB's logging.
package log

import (
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/option"

	"github.com/sirupsen/logrus"
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
