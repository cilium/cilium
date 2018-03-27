// Copyright 2018 Authors of Cilium
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

package flowdebug

import (
	"github.com/sirupsen/logrus"
)

var perFlowDebug = false

// Enable enables per-flow debugging
func Enable() {
	perFlowDebug = true
}

// Enabled reports the status of per-flow debugging
func Enabled() bool {
	return perFlowDebug
}

// Log must be used to log any debug messages emitted per request/message/connection
func Log(l *logrus.Entry, args ...interface{}) {
	if perFlowDebug {
		l.Debug(args...)
	}
}

// Logf must be used to log any debug messages emitted per request/message/connection
func Logf(l *logrus.Entry, format string, args ...interface{}) {
	if perFlowDebug {
		l.Debugf(format, args...)
	}
}
