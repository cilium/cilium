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
	"strings"

	"go.uber.org/zap"
)

// ZapLogger is an Fx event logger that logs events to Zap.
type ZapLogger struct {
	Logger *zap.Logger
}

var _ Logger = (*ZapLogger)(nil)

// LogEvent logs the given event to the provided Zap logger.
func (l *ZapLogger) LogEvent(event Event) {
	switch e := event.(type) {
	case *OnStartExecuting:
		l.Logger.Info("OnStart hook executing",
			zap.String("callee", e.FunctionName),
			zap.String("caller", e.CallerName),
		)
	case *OnStartExecuted:
		if e.Err != nil {
			l.Logger.Info("OnStart hook failed",
				zap.String("callee", e.FunctionName),
				zap.String("caller", e.CallerName),
				zap.Error(e.Err),
			)
		} else {
			l.Logger.Info("OnStart hook executed",
				zap.String("callee", e.FunctionName),
				zap.String("caller", e.CallerName),
				zap.String("runtime", e.Runtime.String()),
			)
		}
	case *OnStopExecuting:
		l.Logger.Info("OnStop hook executing",
			zap.String("callee", e.FunctionName),
			zap.String("caller", e.CallerName),
		)
	case *OnStopExecuted:
		if e.Err != nil {
			l.Logger.Info("OnStop hook failed",
				zap.String("callee", e.FunctionName),
				zap.String("caller", e.CallerName),
				zap.Error(e.Err),
			)
		} else {
			l.Logger.Info("OnStop hook executed",
				zap.String("callee", e.FunctionName),
				zap.String("caller", e.CallerName),
				zap.String("runtime", e.Runtime.String()),
			)
		}
	case *Supplied:
		l.Logger.Info("supplied", zap.String("type", e.TypeName), zap.Error(e.Err))
	case *Provided:
		for _, rtype := range e.OutputTypeNames {
			l.Logger.Info("provided",
				zap.String("constructor", e.ConstructorName),
				zap.String("type", rtype),
			)
		}
		if e.Err != nil {
			l.Logger.Error("error encountered while applying options",
				zap.Error(e.Err))
		}
	case *Invoking:
		// Do not log stack as it will make logs hard to read.
		l.Logger.Info("invoking",
			zap.String("function", e.FunctionName))
	case *Invoked:
		if e.Err != nil {
			l.Logger.Error("invoke failed",
				zap.Error(e.Err),
				zap.String("stack", e.Trace),
				zap.String("function", e.FunctionName))
		}
	case *Stopping:
		l.Logger.Info("received signal",
			zap.String("signal", strings.ToUpper(e.Signal.String())))
	case *Stopped:
		if e.Err != nil {
			l.Logger.Error("stop failed", zap.Error(e.Err))
		}
	case *RollingBack:
		l.Logger.Error("start failed, rolling back", zap.Error(e.StartErr))
	case *RolledBack:
		if e.Err != nil {
			l.Logger.Error("rollback failed", zap.Error(e.Err))
		}
	case *Started:
		if e.Err != nil {
			l.Logger.Error("start failed", zap.Error(e.Err))
		} else {
			l.Logger.Info("started")
		}
	case *LoggerInitialized:
		if e.Err != nil {
			l.Logger.Error("custom logger initialization failed", zap.Error(e.Err))
		} else {
			l.Logger.Info("initialized custom fxevent.Logger", zap.String("function", e.ConstructorName))
		}
	}
}
