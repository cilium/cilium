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

package fxevent

import (
	"fmt"
	"io"
	"strings"
)

// ConsoleLogger is an Fx event logger that attempts to write human-readable
// messages to the console.
//
// Use this during development.
type ConsoleLogger struct {
	W io.Writer
}

var _ Logger = (*ConsoleLogger)(nil)

func (l *ConsoleLogger) logf(msg string, args ...interface{}) {
	fmt.Fprintf(l.W, "[Fx] "+msg+"\n", args...)
}

// LogEvent logs the given event to the provided Zap logger.
func (l *ConsoleLogger) LogEvent(event Event) {
	switch e := event.(type) {
	case *OnStartExecuting:
		l.logf("HOOK OnStart\t\t%s executing (caller: %s)", e.FunctionName, e.CallerName)
	case *OnStartExecuted:
		if e.Err != nil {
			l.logf("HOOK OnStart\t\t%s called by %s failed in %s: %v", e.FunctionName, e.CallerName, e.Runtime, e.Err)
		} else {
			l.logf("HOOK OnStart\t\t%s called by %s ran successfully in %s", e.FunctionName, e.CallerName, e.Runtime)
		}
	case *OnStopExecuting:
		l.logf("HOOK OnStop\t\t%s executing (caller: %s)", e.FunctionName, e.CallerName)
	case *OnStopExecuted:
		if e.Err != nil {
			l.logf("HOOK OnStop\t\t%s called by %s failed in %s: %v", e.FunctionName, e.CallerName, e.Runtime, e.Err)
		} else {
			l.logf("HOOK OnStop\t\t%s called by %s ran successfully in %s", e.FunctionName, e.CallerName, e.Runtime)
		}
	case *Supplied:
		if e.Err != nil {
			l.logf("ERROR\tFailed to supply %v: %v", e.TypeName, e.Err)
		} else if e.ModuleName != "" {
			l.logf("SUPPLY\t%v from module %q", e.TypeName, e.ModuleName)
		} else {
			l.logf("SUPPLY\t%v", e.TypeName, e.ModuleName)
		}
	case *Provided:
		for _, rtype := range e.OutputTypeNames {
			if e.ModuleName != "" {
				l.logf("PROVIDE\t%v <= %v from module %q", rtype, e.ConstructorName, e.ModuleName)
			} else {
				l.logf("PROVIDE\t%v <= %v", rtype, e.ConstructorName)
			}
		}
		if e.Err != nil {
			l.logf("Error after options were applied: %v", e.Err)
		}
	case *Decorated:
		for _, rtype := range e.OutputTypeNames {
			if e.ModuleName != "" {
				l.logf("DECORATE\t%v <= %v from module %q", rtype, e.DecoratorName, e.ModuleName)
			} else {
				l.logf("DECORATE\t%v <= %v", rtype, e.DecoratorName)
			}
		}
		if e.Err != nil {
			l.logf("Error after options were applied: %v", e.Err)
		}
	case *Invoking:
		if e.ModuleName != "" {
			l.logf("INVOKE\t\t%s from module %q", e.FunctionName, e.ModuleName)
		} else {
			l.logf("INVOKE\t\t%s", e.FunctionName)
		}
	case *Invoked:
		if e.Err != nil {
			l.logf("ERROR\t\tfx.Invoke(%v) called from:\n%+vFailed: %v", e.FunctionName, e.Trace, e.Err)
		}
	case *Stopping:
		l.logf("%v", strings.ToUpper(e.Signal.String()))
	case *Stopped:
		if e.Err != nil {
			l.logf("ERROR\t\tFailed to stop cleanly: %v", e.Err)
		}
	case *RollingBack:
		l.logf("ERROR\t\tStart failed, rolling back: %v", e.StartErr)
	case *RolledBack:
		if e.Err != nil {
			l.logf("ERROR\t\tCouldn't roll back cleanly: %v", e.Err)
		}
	case *Started:
		if e.Err != nil {
			l.logf("ERROR\t\tFailed to start: %v", e.Err)
		} else {
			l.logf("RUNNING")
		}
	case *LoggerInitialized:
		if e.Err != nil {
			l.logf("ERROR\t\tFailed to initialize custom logger: %+v", e.Err)
		} else {
			l.logf("LOGGER\tInitialized custom logger from %v", e.ConstructorName)
		}
	}
}
