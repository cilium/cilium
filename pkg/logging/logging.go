// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logging

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/klog/v2"

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

	// DefaultLogFormat is the string representation of the default logrus.Formatter
	// we want to use (possible values: text or json)
	DefaultLogFormat LogFormat = LogFormatText

	// DefaultLogFormatTimestamp is the string representation of the default logrus.Formatter
	// including timestamps.
	// We don't use this for general runtime logs since kubernetes log capture handles those.
	// This is only used for applications such as CNI which is written to disk so we have no
	// way to correlate with other logs.
	DefaultLogFormatTimestamp LogFormat = LogFormatTextTimestamp

	// DefaultLogLevel is the default log level we want to use for our logrus.Formatter
	DefaultLogLevel logrus.Level = logrus.InfoLevel
)

// DefaultLogger is the base logrus logger. It is different from the logrus
// default to avoid external dependencies from writing out unexpectedly
var DefaultLogger = initializeDefaultLogger()

var klogErrorOverrides = []logLevelOverride{
	{
		// TODO: We can drop the misspelled case here once client-go version is bumped to include:
		//	https://github.com/kubernetes/client-go/commit/ae43527480ee9d8750fbcde3d403363873fd3d89
		matcher:     regexp.MustCompile("Failed to update lock (optimitically|optimistically).*falling back to slow path"),
		targetLevel: logrus.InfoLevel,
	},
}

func initializeKLog() error {
	log := DefaultLogger.WithField(logfields.LogSubsys, "klog")

	// Create a new flag set and set error handler
	klogFlags := flag.NewFlagSet("cilium", flag.ExitOnError)

	// Make sure that klog logging variables are initialized so that we can
	// update them from this file.
	klog.InitFlags(klogFlags)

	// Make sure klog does not log to stderr as we want it to control the output
	// of klog so we want klog to log the errors to each writer of each level.
	klogFlags.Set("logtostderr", "false")

	// We don't need all headers because logrus will already print them if
	// necessary.
	klogFlags.Set("skip_headers", "true")

	errWriter, err := severityOverrideWriter(logrus.ErrorLevel, log, klogErrorOverrides)
	if err != nil {
		return fmt.Errorf("failed to setup klog error writer: %w", err)
	}

	klog.SetOutputBySeverity("INFO", log.WriterLevel(logrus.InfoLevel))
	klog.SetOutputBySeverity("WARNING", log.WriterLevel(logrus.WarnLevel))
	klog.SetOutputBySeverity("ERROR", errWriter)
	klog.SetOutputBySeverity("FATAL", log.WriterLevel(logrus.FatalLevel))

	// Do not repeat log messages on all severities in klog
	klogFlags.Set("one_output", "true")

	return nil
}

type logLevelOverride struct {
	matcher     *regexp.Regexp
	targetLevel logrus.Level
}

var (
	LevelPanic = slog.LevelError + 8
	LevelFatal = LevelPanic + 2
)

func levelToPrintFunc(log *logrus.Entry, level logrus.Level) (func(args ...any), error) {
	var printFunc func(args ...any)
	switch level {
	case logrus.InfoLevel:
		printFunc = log.Info
	case logrus.WarnLevel:
		printFunc = log.Warn
	case logrus.ErrorLevel:
		printFunc = log.Error
	default:
		return nil, fmt.Errorf("unsupported log level %q", level)
	}
	return printFunc, nil
}

func severityOverrideWriter(level logrus.Level, log *logrus.Entry, overrides []logLevelOverride) (*io.PipeWriter, error) {
	printFunc, err := levelToPrintFunc(log, level)
	if err != nil {
		return nil, err
	}
	reader, writer := io.Pipe()

	for _, override := range overrides {
		_, err := levelToPrintFunc(log, override.targetLevel)
		if err != nil {
			return nil, fmt.Errorf("failed to validate klog matcher level overrides (%s -> %s): %w",
				override.matcher.String(), level, err)
		}
	}
	go writerScanner(log, reader, printFunc, overrides)
	return writer, nil
}

// writerScanner scans the input from the reader and writes it to the appropriate
// log print func.
// In cases where the log message is overridden, that will be emitted via the specified
// target log level logger function.
//
// Based on code from logrus WriterLevel implementation [1]
//
// [1] https://github.com/sirupsen/logrus/blob/v1.9.3/writer.go#L66-L97
func writerScanner(
	entry *logrus.Entry,
	reader *io.PipeReader,
	defaultPrintFunc func(args ...any),
	overrides []logLevelOverride) {

	defer reader.Close()

	scanner := bufio.NewScanner(reader)

	// Set the buffer size to the maximum token size to avoid buffer overflows
	scanner.Buffer(make([]byte, bufio.MaxScanTokenSize), bufio.MaxScanTokenSize)

	// Define a split function to split the input into chunks of up to 64KB
	chunkSize := bufio.MaxScanTokenSize // 64KB
	splitFunc := func(data []byte, atEOF bool) (int, []byte, error) {
		if len(data) >= chunkSize {
			return chunkSize, data[:chunkSize], nil
		}

		return bufio.ScanLines(data, atEOF)
	}

	// Use the custom split function to split the input
	scanner.Split(splitFunc)

	// Scan the input and write it to the logger using the specified print function
	for scanner.Scan() {
		line := scanner.Text()
		matched := false
		for _, override := range overrides {
			printFn, err := levelToPrintFunc(entry, override.targetLevel)
			if err != nil {
				entry.WithError(err).WithField("matcher", override.matcher).
					Error("BUG: failed to get printer for klog override matcher")
				continue
			}
			if override.matcher.FindString(line) != "" {
				printFn(strings.TrimRight(line, "\r\n"))
				matched = true
				break
			}
		}
		if !matched {
			defaultPrintFunc(strings.TrimRight(scanner.Text(), "\r\n"))
		}
	}

	if err := scanner.Err(); err != nil {
		entry.WithError(err).Error("klog logrus override scanner stopped scanning with an error. " +
			"This may mean that k8s client-go logs will no longer be emitted")
	}
}

// LogOptions maps configuration key-value pairs related to logging.
type LogOptions map[string]string

// initializeDefaultLogger returns a logrus Logger with the default logging
// settings.
func initializeDefaultLogger() (logger *logrus.Logger) {
	logger = logrus.New()
	logger.SetFormatter(GetFormatter(DefaultLogFormatTimestamp))
	logger.SetLevel(DefaultLogLevel)
	return
}

// GetLogLevel returns the log level specified in the provided LogOptions. If
// it is not set in the options, it will return the default level.
func (o LogOptions) GetLogLevel() (level logrus.Level) {
	levelOpt, ok := o[LevelOpt]
	if !ok {
		return DefaultLogLevel
	}

	var err error
	if level, err = logrus.ParseLevel(levelOpt); err != nil {
		logrus.WithError(err).Warning("Ignoring user-configured log level")
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
		logrus.WithError(
			fmt.Errorf("incorrect log format configured '%s', expected 'text', 'text-ts', 'json' or 'json-ts'", formatOpt),
		).Warning("Ignoring user-configured log format")
		return DefaultLogFormatTimestamp
	}

	return LogFormat(formatOpt)
}

// SetLogLevel updates the DefaultLogger with a new logrus.Level
func SetLogLevel(logLevel logrus.Level) {
	DefaultLogger.SetLevel(logLevel)
	DefaultLogger.SetReportCaller(logLevel == logrus.DebugLevel)
}

// SetDefaultLogLevel updates the DefaultLogger with the DefaultLogLevel
func SetDefaultLogLevel() {
	SetLogLevel(DefaultLogLevel)
}

// SetLogLevelToDebug updates the DefaultLogger with the logrus.DebugLevel
func SetLogLevelToDebug() {
	SetLogLevel(logrus.DebugLevel)
}

// SetLogFormat updates the DefaultLogger with a new LogFormat
func SetLogFormat(logFormat LogFormat) {
	DefaultLogger.SetFormatter(GetFormatter(logFormat))
}

// SetDefaultLogFormat updates the DefaultLogger with the DefaultLogFormat
func SetDefaultLogFormat() {
	DefaultLogger.SetFormatter(GetFormatter(DefaultLogFormatTimestamp))
}

// AddHooks adds additional logrus hook to default logger
func AddHooks(hooks ...logrus.Hook) {
	for _, hook := range hooks {
		DefaultLogger.AddHook(hook)
	}
}

// SetupLogging sets up each logging service provided in loggers and configures
// each logger with the provided logOpts.
func SetupLogging(loggers []string, logOpts LogOptions, tag string, debug bool) error {
	// Bridge klog to logrus. Note that this will open multiple pipes and fork
	// background goroutines that are not cleaned up.
	initializeKLog()

	if debug {
		logOpts[LevelOpt] = "debug"
	}

	initializeSlog(logOpts, loggers)

	// Updating the default log format
	SetLogFormat(logOpts.GetLogFormat())

	// Set default logger to output to stdout if no loggers are provided.
	if len(loggers) == 0 {
		// TODO: switch to a per-logger version when we upgrade to logrus >1.0.3
		logrus.SetOutput(os.Stdout)
	}

	// Updating the default log level, overriding the log options if the debug arg is being set
	if debug {
		SetLogLevelToDebug()
	} else {
		SetLogLevel(logOpts.GetLogLevel())
	}

	// always suppress the default logger so libraries don't print things
	logrus.SetLevel(logrus.PanicLevel)

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

	return nil
}

// GetFormatter returns a configured logrus.Formatter with some specific values
// we want to have
func GetFormatter(format LogFormat) logrus.Formatter {
	switch format {
	case LogFormatText:
		return &logrus.TextFormatter{
			DisableTimestamp: true,
			DisableColors:    true,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyFile: "source",
			},
			CallerPrettyfier: func(f *runtime.Frame) (function string, file string) {
				file = fmt.Sprintf("%s:%d", f.File, f.Line)
				return
			},
		}
	case LogFormatTextTimestamp:
		return &logrus.TextFormatter{
			DisableTimestamp: false,
			TimestampFormat:  time.RFC3339Nano,
			DisableColors:    true,
			FieldMap: logrus.FieldMap{
				logrus.FieldKeyFile: "source",
			},
			CallerPrettyfier: func(f *runtime.Frame) (function string, file string) {
				file = fmt.Sprintf("%s:%d", f.File, f.Line)
				return
			},
		}
	case LogFormatJSON:
		return &logrus.JSONFormatter{
			DisableTimestamp: true,
		}
	case LogFormatJSONTimestamp:
		return &logrus.JSONFormatter{
			DisableTimestamp: false,
			TimestampFormat:  time.RFC3339Nano,
		}
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
			DefaultLogger.Fatal(err)
		}
		if ok {
			keysToValidate[k] = v
		}
	}
	return keysToValidate
}

// MultiLine breaks a multi line text into individual log entries and calls the
// logging function to log each entry
func MultiLine(logFn func(args ...any), output string) {
	scanner := bufio.NewScanner(bytes.NewReader([]byte(output)))
	for scanner.Scan() {
		logFn(scanner.Text())
	}
}

// CanLogAt returns whether a log message at the given level would be
// logged by the given logger.
func CanLogAt(logger *logrus.Logger, level logrus.Level) bool {
	return GetLevel(logger) >= level
}

// GetLevel returns the log level of the given logger.
func GetLevel(logger *logrus.Logger) logrus.Level {
	return logrus.Level(atomic.LoadUint32((*uint32)(&logger.Level)))
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
