// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"golang.org/x/exp/slices"
)

type FxLogger struct {
	logrus.FieldLogger

	sups  []*fxevent.Supplied
	ctors []*fxevent.Provided
}

func FxLoggerOption(log logrus.FieldLogger) fx.Option {
	return fx.WithLogger(func() fxevent.Logger { return NewFxLogger(log) })
}

func NewFxLogger(log logrus.FieldLogger) *FxLogger {
	return &FxLogger{FieldLogger: log}
}

func (log *FxLogger) PrintObjects() {
	slices.SortFunc(log.sups, func(a, b *fxevent.Supplied) bool {
		return a.ModuleName < b.ModuleName || (a.ModuleName == b.ModuleName && a.TypeName < b.TypeName)
	})

	fmt.Print("Supplied objects:\n\n")
	for _, sup := range log.sups {
		if sup.ModuleName != "" {
			fmt.Printf("  🎁️ %s from %s\n", sup.TypeName, sup.ModuleName)
		} else {
			fmt.Printf("  🎁️ %s\n", sup.TypeName)
		}
		fmt.Println()
	}

	slices.SortFunc(log.ctors, func(a, b *fxevent.Provided) bool {
		return a.ModuleName < b.ModuleName || (a.ModuleName == b.ModuleName && a.ConstructorName < b.ConstructorName)
	})
	// Collapse constructors by ModuleName
	ctorsByModule := make(map[string][]*fxevent.Provided)
	for _, ctor := range log.ctors {
		ctorsByModule[ctor.ModuleName] = append(ctorsByModule[ctor.ModuleName], ctor)
	}

	fmt.Print("Constructors:\n\n")
	for _, ctor := range ctorsByModule[""] {
		fmt.Printf("  🛠️  %s:\n", ctor.ConstructorName)
		for _, rtype := range ctor.OutputTypeNames {
			fmt.Printf("    • %s\n", rtype)
		}
		if ctor.Err != nil {
			fmt.Printf("  ❌%s error: %s\n", ctor.ConstructorName, strings.Replace(ctor.Err.Error(), ":", ":\n\t", -1))
		}
		fmt.Println()
	}
	for modName, ctors := range ctorsByModule {
		if modName == "" {
			continue
		}

		fmt.Printf("  🛠️  %s:\n", modName)
		for _, ctor := range ctors {
			for _, rtype := range ctor.OutputTypeNames {
				fmt.Printf("    • %s\n", rtype)
			}
			if ctor.Err != nil {
				fmt.Printf("  ❌%s error: %s\n", ctor.ConstructorName, strings.Replace(ctor.Err.Error(), ":", ":\n\t", -1))
			}
		}
		fmt.Println()
	}
}

func (log *FxLogger) LogEvent(event fxevent.Event) {
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
		log.sups = append(log.sups, e)

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
		log.ctors = append(log.ctors, e)

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
				Debug("Invoke failed")
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
				Debug("Initialized custom fxevent.Logger")
		}
	}
}
