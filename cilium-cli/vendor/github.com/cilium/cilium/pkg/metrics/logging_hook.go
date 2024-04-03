// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	metricsInitialized chan struct{} = make(chan struct{})
	flushMetrics                     = sync.Once{}
)

// FlushLoggingMetrics will cause all logging hook metrics accumulated prior
// to the errors_warnings metrics being registered with the Prometheus collector
// to be incremented to their respective errors_warnings metrics tuple.
func FlushLoggingMetrics() {
	flushMetrics.Do(func() {
		if metricsInitialized != nil {
			close(metricsInitialized)
			metricsInitialized = nil
		}
	})
}

// LoggingHook is a hook for logrus which counts error and warning messages as a
// Prometheus metric.
type LoggingHook struct {
	errs, warn atomic.Uint64
}

// NewLoggingHook returns a new instance of LoggingHook for the given Cilium
// component.
func NewLoggingHook() *LoggingHook {
	lh := &LoggingHook{}
	go func() {
		// This channel is closed after registry is created. At this point if the errs/warnings metric
		// is enabled we flush counts of errors/warnings we collected before the registry was created.
		// This is a hack to ensure that errors/warnings collected in the pre hive initialization
		// phase are emitted as metrics.
		// Because the ErrorsWarnings metric is a counter, this means that the rate of these errors won't be
		// accurate, however init errors can only happen during initialization so it probably doesn't make
		// a big difference in practice.
		<-metricsInitialized
		ErrorsWarnings.WithLabelValues(logrus.ErrorLevel.String(), "init").Add(float64(lh.errs.Load()))
		ErrorsWarnings.WithLabelValues(logrus.WarnLevel.String(), "init").Add(float64(lh.warn.Load()))
	}()
	return lh
}

// Levels returns the list of logging levels on which the hook is triggered.
func (h *LoggingHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.ErrorLevel,
		logrus.WarnLevel,
	}
}

// Fire is the main method which is called every time when logger has an error
// or warning message.
func (h *LoggingHook) Fire(entry *logrus.Entry) error {
	// Get information about subsystem from logging entry field.
	iSubsystem, ok := entry.Data[logfields.LogSubsys]
	if !ok {
		serializedEntry, err := entry.String()
		if err != nil {
			return fmt.Errorf("log entry cannot be serialized and doesn't contain 'subsys' field")
		}
		return fmt.Errorf("log entry doesn't contain 'subsys' field: %s", serializedEntry)
	}
	subsystem, ok := iSubsystem.(string)
	if !ok {
		return fmt.Errorf("type of the 'subsystem' log entry field is not string but %s", reflect.TypeOf(iSubsystem))
	}

	// We count errors/warnings outside of the prometheus metric.
	switch entry.Level {
	case logrus.ErrorLevel:
		h.errs.Add(1)
	case logrus.WarnLevel:
		h.warn.Add(1)
	}

	// Increment the metric.
	ErrorsWarnings.WithLabelValues(entry.Level.String(), subsystem).Inc()

	return nil
}
