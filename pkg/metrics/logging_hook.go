// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

var slogDupAttrDetection = false

func init() {
	// Detector to check if we have duplicate attributes in slog logging hook.
	slogDupAttrDetection, _ = strconv.ParseBool(os.Getenv("CILIUM_SLOG_DUP_ATTR_DETECTOR"))
}

var (
	metricsInitialized = make(chan struct{})
	flushMetrics       = sync.Once{}
)

// FlushLoggingMetrics will cause all logging hook metrics accumulated prior
// to the errors_warnings metrics being registered with the Prometheus collector
// to be incremented to their respective errors_warnings metrics tuple.
func FlushLoggingMetrics() {
	flushMetrics.Do(func() {
		if metricsInitialized != nil {
			close(metricsInitialized)
		}
	})
}

// LoggingHook is a hook for logrus which counts error and warning messages as a
// Prometheus metric.
type LoggingHook struct {
	errs, warn *atomic.Uint64
	attrs      map[string]slog.Value
}

// NewLoggingHook returns a new instance of LoggingHook for the given Cilium
// component.
func NewLoggingHook() *LoggingHook {
	lh := &LoggingHook{
		errs:  &atomic.Uint64{},
		warn:  &atomic.Uint64{},
		attrs: make(map[string]slog.Value),
	}
	go func() {
		// This channel is closed after registry is created. At this point if the errs/warnings metric
		// is enabled we flush counts of errors/warnings we collected before the registry was created.
		// This is a hack to ensure that errors/warnings collected in the pre hive initialization
		// phase are emitted as metrics.
		// Because the ErrorsWarnings metric is a counter, this means that the rate of these errors won't be
		// accurate, however init errors can only happen during initialization so it probably doesn't make
		// a big difference in practice.
		<-metricsInitialized
		metricsInitialized = nil
		ErrorsWarnings.WithLabelValues(slog.LevelError.String(), "init").Add(float64(lh.errs.Load()))
		ErrorsWarnings.WithLabelValues(slog.LevelWarn.String(), "init").Add(float64(lh.warn.Load()))
	}()
	return lh
}

func (h *LoggingHook) Enabled(_ context.Context, level slog.Level) bool {
	// Only handle Error and Warning logging records.
	return level >= slog.LevelWarn
}

func (h *LoggingHook) Handle(_ context.Context, record slog.Record) error {
	// Get information about subsystem from logging entry field.
	logSysValue, logSysPresent := h.attrs[logfields.LogSubsys]
	if slogDupAttrDetection {
		var i int
		if logSysPresent {
			i = 1
		}
		record.Attrs(func(attr slog.Attr) bool {
			if attr.Key == logfields.LogSubsys {
				logSysPresent = true
				logSysValue = attr.Value
				i++
			}
			if v, ok := h.attrs[attr.Key]; ok {
				panic(fmt.Sprintf("duplicate attribute: %q. existing-value=%s, new-value=%s", attr.Key, v, attr.Value))
			}
			if i > 1 {
				panic(fmt.Sprintf("more than one subsys found in %s", record.Message))
			}
			return true
		})
		if i > 1 {
			panic(fmt.Sprintf("more than one subsys found in %s", record.Message))
		}
	}
	if logSysPresent && logSysValue.Kind() != slog.KindString {
		return fmt.Errorf("type of the 'subsystem' log entry field is not string but %s", logSysValue)
	}

	// We count errors/warnings outside of the prometheus metric.
	switch record.Level {
	case slog.LevelError:
		h.errs.Add(1)
	case slog.LevelWarn:
		h.warn.Add(1)
	}

	// Increment the metric.
	if logSysPresent {
		ErrorsWarnings.WithLabelValues(record.Level.String(), logSysValue.String()).Inc()
	} else {
		ErrorsWarnings.WithLabelValues(record.Level.String(), "unspecified").Inc()
	}

	return nil
}

func (h *LoggingHook) WithAttrs(attrs []slog.Attr) slog.Handler {
	lh := &LoggingHook{errs: h.errs, warn: h.warn}
	lh.attrs = maps.Clone(h.attrs)
	for _, attr := range attrs {
		if slogDupAttrDetection {
			if v, ok := h.attrs[attr.Key]; ok {
				panic(fmt.Sprintf("duplicate attribute: %q. existing-value=%s, new-value=%s", attr.Key, v, attr.Value))
			}
		}
		lh.attrs[attr.Key] = attr.Value
	}
	return lh
}

func (h *LoggingHook) WithGroup(name string) slog.Handler {
	return &LoggingHook{errs: h.errs, warn: h.warn, attrs: maps.Clone(h.attrs)}
}
