// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package metrics

import (
	"fmt"
	"reflect"

	"github.com/cilium/cilium/pkg/components"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
)

// LoggingHook is a hook for logrus which counts error and warning messages as a
// Prometheus metric.
type LoggingHook struct {
	metric CounterVec
}

// NewLoggingHook returns a new instance of LoggingHook for the given Cilium
// component.
func NewLoggingHook(component string) *LoggingHook {
	// NOTE(mrostecki): For now errors and warning metric exists only for Cilium
	// daemon, but support of Prometheus metrics in some other components (i.e.
	// cilium-health - GH-4268) is planned.

	// Pick a metric for the component.
	var metric CounterVec
	switch component {
	case components.CiliumAgentName:
		metric = ErrorsWarnings
	case components.CiliumOperatortName:
		metric = ErrorsWarnings
	default:
		panic(fmt.Sprintf("component %s is unsupported by LoggingHook", component))
	}

	return &LoggingHook{metric: metric}
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
