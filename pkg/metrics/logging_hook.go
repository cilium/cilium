// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"fmt"
	"reflect"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type loggerHookMetrics struct {
	ErrorsWarnings metric.Vec[metric.Counter]
}

func NewLoggingHookMetrics() *loggerHookMetrics {
	return &loggerHookMetrics{
		ErrorsWarnings: metric.NewCounterVec(metric.CounterOpts{
			Namespace:        Namespace,
			Name:             "errors_warnings_total",
			Help:             "Number of total errors in cilium-agent instances",
			EnabledByDefault: true,
		}, metric.LabelDescriptions{
			{Name: "level", Description: "Log level", KnownValues: []metric.KnownValue{
				{Name: "error"},
				{Name: "warning"},
			}},
			{Name: "subsystem"},
		}),
	}
}

// LoggingHook is a hook for logrus which counts error and warning messages as a
// Prometheus metric.
type LoggingHook struct {
	metric metric.Vec[metric.Counter]
}

// NewLoggingHook returns a new instance of LoggingHook for the given Cilium
// component.
func NewLoggingHook(metrics *loggerHookMetrics) *LoggingHook {
	return &LoggingHook{metric: metrics.ErrorsWarnings}
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

	// Increment the metric.
	h.metric.WithLabelValues(entry.Level.String(), subsystem).Inc()

	return nil
}
