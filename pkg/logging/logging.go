// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type LogFormat string

const (
	Syslog    = "syslog"
	LevelOpt  = "level"
	FormatOpt = "format"
	WriterOpt = "writer"

	StdOutOpt = "stdout"
	StdErrOpt = "stderr"

	LogFormatText          LogFormat = "text"
	LogFormatTextTimestamp LogFormat = "text-ts"
	LogFormatJSON          LogFormat = "json"
	LogFormatJSONTimestamp LogFormat = "json-ts"

	// DefaultLogFormatTimestamp is the string representation of the default log
	// format including timestamps.
	// We don't use this for general runtime logs since kubernetes log capture handles those.
	// This is only used for applications such as CNI which is written to disk so we have no
	// way to correlate with other logs.
	DefaultLogFormatTimestamp LogFormat = LogFormatTextTimestamp

	// DefaultLogLevel is the default log level we want to use for our logs.
	DefaultLogLevel = slog.LevelInfo
)

var (
	LevelPanic = slog.LevelError + 8
	LevelFatal = LevelPanic + 2
)
var (
	levelPanicValue = slog.AnyValue(LevelPanic)
	levelFatalValue = slog.AnyValue(LevelFatal)
)

// LogOptions maps configuration key-value pairs related to logging.
type LogOptions map[string]string

// GetLogLevel returns the log level specified in the provided LogOptions. If
// it is not set in the options, it will return the default level.
func (o LogOptions) GetLogLevel() (level slog.Level) {
	levelOpt, ok := o[LevelOpt]
	if !ok {
		return DefaultLogLevel
	}

	var err error
	if level, err = ParseLevel(levelOpt); err != nil {
		DefaultSlogLogger.Warn("Ignoring user-configured log level", logfields.Error, err)
		return DefaultLogLevel
	}

	return
}

// GetLogFormat returns the log format specified in the provided LogOptions. If
// it is not set in the options or is invalid, it will return the default format.
func (o LogOptions) GetLogFormat() LogFormat {
	formatOpt, ok := o[FormatOpt]
	if !ok {
		return DefaultLogFormatTimestamp
	}

	formatOpt = strings.ToLower(formatOpt)
	re := regexp.MustCompile(`^(text|text-ts|json|json-ts)$`)
	if !re.MatchString(formatOpt) {
		DefaultSlogLogger.Warn(
			"Ignoring user-configured log format",
			logfields.Error, fmt.Errorf("incorrect log format configured '%s', expected 'text', 'text-ts', 'json' or 'json-ts'", formatOpt),
		)
		return DefaultLogFormatTimestamp
	}

	return LogFormat(formatOpt)
}

// SetLogLevel updates the DefaultLogger with a new slog.Level
func SetLogLevel(logLevel slog.Level) {
	slogLeveler.Set(logLevel)
}

// SetDefaultLogLevel updates the DefaultLogger with the DefaultLogLevel
func SetDefaultLogLevel() {
	SetLogLevel(DefaultLogLevel)
}

// SetLogLevelToDebug updates the DefaultLogger with the logrus.DebugLevel
func SetLogLevelToDebug() {
	slogLeveler.Set(slog.LevelDebug)
}

// AddHandlers adds additional logrus hook to default logger
func AddHandlers(hooks ...slog.Handler) {
	defaultMultiSlogHandler.AddHandlers(hooks...)
}

// SetupLogging sets up each logging service provided in loggers and configures
// each logger with the provided logOpts.
func SetupLogging(loggers []string, logOpts LogOptions, tag string, debug bool) error {
	if debug {
		logOpts[LevelOpt] = "debug"
	}

	initializeSlog(logOpts, loggers)

	// always suppress the default logger so libraries don't print things
	slog.SetLogLoggerLevel(LevelPanic)

	// Iterate through all provided loggers and configure them according
	// to user-provided settings.
	for _, logger := range loggers {
		switch logger {
		case Syslog:
			if err := setupSyslog(logOpts, tag, debug); err != nil {
				return fmt.Errorf("failed to set up syslog: %w", err)
			}
		default:
			return fmt.Errorf("provided log driver %q is not a supported log driver", logger)
		}
	}

	lock.SetLogger(DefaultSlogLogger)

	// Bridge klog to slog. Note that this will open multiple pipes and fork
	// background goroutines that are not cleaned up.
	err := initializeKLog(DefaultSlogLogger)
	if err != nil {
		return err
	}

	return nil
}

// validateOpts iterates through all of the keys and values in logOpts, and errors out if
// the key in logOpts is not a key in supportedOpts, or the value of corresponding key is
// not listed in the value of validKVs.
func (o LogOptions) validateOpts(logDriver string, supportedOpts map[string]bool, validKVs map[string][]string) error {
	for k, v := range o {
		if !supportedOpts[k] {
			return fmt.Errorf("provided configuration key %q is not supported as a logging option for log driver %s", k, logDriver)
		}
		if validValues, ok := validKVs[k]; ok {
			valid := slices.Contains(validValues, v)
			if !valid {
				return fmt.Errorf("provided configuration value %q is not a valid value for %q in log driver %s, valid values: %v", v, k, logDriver, validValues)
			}

		}
	}
	return nil
}

// getLogDriverConfig returns a map containing the key-value pairs that start
// with string logDriver from map logOpts.
func getLogDriverConfig(logDriver string, logOpts LogOptions) LogOptions {
	keysToValidate := make(LogOptions)
	for k, v := range logOpts {
		ok, err := regexp.MatchString(logDriver+".*", k)
		if err != nil {
			Fatal(DefaultSlogLogger, err.Error())
		}
		if ok {
			keysToValidate[k] = v
		}
	}
	return keysToValidate
}

// GetSlogLevel returns the log level of the given sloger.
func GetSlogLevel(logger FieldLogger) slog.Level {
	switch {
	case logger.Enabled(context.Background(), slog.LevelDebug):
		return slog.LevelDebug
	case logger.Enabled(context.Background(), slog.LevelInfo):
		return slog.LevelInfo
	case logger.Enabled(context.Background(), slog.LevelWarn):
		return slog.LevelWarn
	case logger.Enabled(context.Background(), slog.LevelError):
		return slog.LevelError
	case logger.Enabled(context.Background(), LevelPanic):
		return LevelPanic
	case logger.Enabled(context.Background(), LevelFatal):
		return LevelFatal
	}
	return slog.LevelInfo
}

// ParseLevel takes a string level and returns the slog log level constant.
func ParseLevel(lvl string) (slog.Level, error) {
	switch strings.ToUpper(lvl) {
	case "DEBUG":
		return slog.LevelDebug, nil
	case "INFO":
		return slog.LevelInfo, nil
	case "WARN", "WARNING":
		return slog.LevelWarn, nil
	case "ERROR":
		return slog.LevelError, nil
	case "PANIC":
		return LevelPanic, nil
	case "FATAL":
		return LevelFatal, nil
	default:
		return slog.LevelInfo, errors.New("unknown level " + lvl)
	}
}
