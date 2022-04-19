package cmd

import (
	"strings"

	"github.com/sirupsen/logrus"
	"go.uber.org/fx/fxevent"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type appLogger struct {
	*logrus.Entry
}

func newAppLogger() fxevent.Logger {
	return appLogger{
		logging.DefaultLogger.WithField(logfields.LogSubsys, "daemon-app"),
	}
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
		l.WithError(e.Err).Debug("supplied")
	case *fxevent.Provided:
		l := log.WithField("constructor", e.ConstructorName)
		if len(e.ModuleName) != 0 {
			l = l.WithField("module", e.ModuleName)
		}

		for _, rtype := range e.OutputTypeNames {
			l.WithField("type", rtype).Debug("provided")
		}
		if e.Err != nil {
			l.WithError(e.Err).
				Error("error encountered while applying options")
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
				Error("error encountered while applying options")
		}
	case *fxevent.Invoking:
		l := log.WithField("function", e.FunctionName)
		if len(e.ModuleName) != 0 {
			l = l.WithField("module", e.ModuleName)
		}
		l.Debug("invoking")
	case *fxevent.Invoked:
		if e.Err != nil {
			l := log.WithError(e.Err)
			if len(e.ModuleName) != 0 {
				l = l.WithField("module", e.ModuleName)
			}
			l.WithField("stack", e.Trace).
				WithField("function", e.FunctionName).
				Error("invoke failed")
		}
	case *fxevent.Stopping:
		log.WithField("signal", strings.ToUpper(e.Signal.String())).
			Info("received signal")

	case *fxevent.Stopped:
		if e.Err != nil {
			log.WithError(e.Err).Error("stop failed")
		}
	case *fxevent.RollingBack:
		log.WithError(e.StartErr).Error("start failed, rolling back")
	case *fxevent.RolledBack:
		if e.Err != nil {
			log.WithError(e.Err).Error("rollback failed")
		}
	case *fxevent.Started:
		if e.Err != nil {
			log.WithError(e.Err).Error("start failed")
		} else {
			log.Info("started")
		}
	case *fxevent.LoggerInitialized:
		if e.Err != nil {
			log.WithError(e.Err).Error("custom logger initialization failed")
		} else {
			log.WithField("function", e.ConstructorName).
				Info("initialized custom fxevent.Logger")
		}
	}
}
