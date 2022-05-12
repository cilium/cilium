// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"strings"

	"github.com/sirupsen/logrus"
	"go.uber.org/fx/fxevent"
)

type appLogger struct {
	*logrus.Entry
}

func newAppLogger() fxevent.Logger {
	return appLogger{Entry: log}
}

func (log appLogger) LogEvent(event fxevent.Event) {
	switch e := event.(type) {
	case *fxevent.OnStartExecuting:
		log.WithField("callee", e.FunctionName).
			WithField("caller", e.CallerName).
			Debug("OnStart hook executing")

	case *fxevent.OnStartExecuted:
		if e.Err != nil {
			log.WithField("callee", e.FunctionName).
				WithField("caller", e.CallerName).
				WithError(e.Err).
				Debug("OnStart hook failed")
		} else {
			log.WithField("callee", e.FunctionName).
				WithField("caller", e.CallerName).
				WithField("runtime", e.Runtime.String()).
				Debug("OnStart hook executed")
		}

	case *fxevent.OnStopExecuting:
		log.WithField("callee", e.FunctionName).
			WithField("caller", e.CallerName).
			Debug("OnStop hook executing")

	case *fxevent.OnStopExecuted:
		if e.Err != nil {
			log.WithField("callee", e.FunctionName).
				WithField("caller", e.CallerName).
				WithError(e.Err).
				Error("OnStop hook failed")
		} else {
			log.WithField("callee", e.FunctionName).
				WithField("caller", e.CallerName).
				WithField("runtime", e.Runtime.String()).
				Debug("OnStop hook executed")
		}

	case *fxevent.Supplied:
		l := log.WithField("type", e.TypeName)
		if len(e.ModuleName) != 0 {
			l = l.WithField("module", e.ModuleName)
		}
		if e.Err != nil {
			l = l.WithError(e.Err)
		}
		l.Debug("Supplied")

	case *fxevent.Provided:
		l := log.WithField("constructor", e.ConstructorName)
		if len(e.ModuleName) != 0 {
			l = l.WithField("module", e.ModuleName)
		}

		for _, rtype := range e.OutputTypeNames {
			l.WithField("type", rtype).Debug("Provided")
		}
		if e.Err != nil {
			l.WithError(e.Err).
				Error("Error encountered while applying options")
		}

	case *fxevent.Decorated:
		l := log.WithField("decorator", e.DecoratorName)
		if len(e.ModuleName) != 0 {
			l = l.WithField("module", e.ModuleName)
		}
		for _, rtype := range e.OutputTypeNames {
			l.WithField("type", rtype).Debug("decorated")
		}
		if e.Err != nil {
			l.WithError(e.Err).
				Error("Error encountered while applying options")
		}

	case *fxevent.Invoking:
		l := log.WithField("function", e.FunctionName)
		if len(e.ModuleName) != 0 {
			l = l.WithField("module", e.ModuleName)
		}
		l.Debug("Invoking")

	case *fxevent.Invoked:
		if e.Err != nil {
			l := log.WithError(e.Err)
			if len(e.ModuleName) != 0 {
				l = l.WithField("module", e.ModuleName)
			}
			l.WithField("stack", e.Trace).
				WithField("function", e.FunctionName).
				Error("Invoke failed")
		}

	case *fxevent.Stopping:
		log.WithField("signal", strings.ToUpper(e.Signal.String())).
			Info("Stopping")

	case *fxevent.Stopped:
		if e.Err != nil {
			log.WithError(e.Err).Error("Stop failed")
		} else {
			log.Info("Stopped")
		}

	case *fxevent.RollingBack:
		log.WithError(e.StartErr).Error("Start failed, rolling back")

	case *fxevent.RolledBack:
		if e.Err != nil {
			log.WithError(e.Err).Error("Rollback failed")
		}

	case *fxevent.Started:
		if e.Err != nil {
			log.WithError(e.Err).Error("Start failed")
		} else {
			log.Info("Started")
		}

	case *fxevent.LoggerInitialized:
		if e.Err != nil {
			log.WithError(e.Err).Error("Custom logger initialization failed")
		} else {
			log.WithField("function", e.ConstructorName).
				Info("Initialized custom fxevent.Logger")
		}
	}
}
