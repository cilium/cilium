// Copyright (c) 2021 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package fx

import (
	"go.uber.org/fx/fxevent"
)

// logBuffer will buffer all messages until a logger has been
// initialized.
type logBuffer struct {
	events []fxevent.Event
	logger fxevent.Logger
}

// LogEvent buffers or logs an event.
func (l *logBuffer) LogEvent(event fxevent.Event) {
	if l.logger == nil {
		l.events = append(l.events, event)
	} else {
		l.logger.LogEvent(event)
	}
}

// Connect flushes out all buffered events to a logger and resets them.
func (l *logBuffer) Connect(logger fxevent.Logger) {
	l.logger = logger
	for _, e := range l.events {
		logger.LogEvent(e)
	}
	l.events = nil
}
