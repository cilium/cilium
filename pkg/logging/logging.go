// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package logging

import (
	"bufio"
	"bytes"
	"fmt"
	"log/syslog"
	"os"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
)

const (
	SLevel   = "syslog.level"
	Syslog   = "syslog"
	LevelOpt = "level"
)

var (
	// DefaultLogger is the base logrus logger. It is different from the logrus
	// default to avoid external dependencies from writing out unexpectedly
	DefaultLogger = InitializeDefaultLogger()

	// DefaultLogLevelStr is the string representation of DefaultLogLevel. It
	// is used to allow for injection of the logging level via go's ldflags in
	// unit tests, as only injection with strings via ldflags is allowed.
	DefaultLogLevelStr = "info"

	// syslogOpts is the set of supported options for syslog configuration.
	syslogOpts = map[string]bool{
		"syslog.level": true,
	}

	// syslogLevelMap maps logrus.Level values to syslog.Priority levels.
	syslogLevelMap = map[logrus.Level]syslog.Priority{
		logrus.PanicLevel: syslog.LOG_ALERT,
		logrus.FatalLevel: syslog.LOG_CRIT,
		logrus.ErrorLevel: syslog.LOG_ERR,
		logrus.WarnLevel:  syslog.LOG_WARNING,
		logrus.InfoLevel:  syslog.LOG_INFO,
		logrus.DebugLevel: syslog.LOG_DEBUG,
	}

	// LevelStringToLogrusLevel maps string representations of logrus.Level into
	// their corresponding logrus.Level.
	LevelStringToLogrusLevel = map[string]logrus.Level{
		"panic":   logrus.PanicLevel,
		"error":   logrus.ErrorLevel,
		"warning": logrus.WarnLevel,
		"info":    logrus.InfoLevel,
		"debug":   logrus.DebugLevel,
	}

	logOptions = LogOptions{}
)

// LogOptions maps configuration key-value pairs related to logging.
type LogOptions map[string]string

// InitializeDefaultLogger returns a logrus Logger with a custom text formatter.
func InitializeDefaultLogger() *logrus.Logger {
	logger := logrus.New()
	logger.Formatter = setupFormatter()
	logger.SetLevel(LevelStringToLogrusLevel[DefaultLogLevelStr])
	return logger
}

// GetLogLevelFromConfig returns the log level provided via global
// configuration. If the logging level is invalid, ok will be false.
func GetLogLevelFromConfig() (logrus.Level, bool) {
	return logOptions.GetLogLevel()
}

// GetLogLevel returns the log level specified in the provided LogOptions. If
// it is not set in the options, ok will be false.
func (o LogOptions) GetLogLevel() (logrus.Level, bool) {
	lvl, ok := LevelStringToLogrusLevel[strings.ToLower(o[LevelOpt])]
	return lvl, ok
}

// configureLogLevelFromOptions returns the log level based off of the value of
// LevelOpt in o, or the default log level if the value in the map is invalid or
// not set.
func (o LogOptions) configureLogLevelFromOptions() logrus.Level {
	var level logrus.Level
	if levelOpt, ok := o[LevelOpt]; ok {
		if convertedLevel, ok := o.GetLogLevel(); ok {
			level = convertedLevel
		} else {
			// Invalid configuration provided, go with default.
			DefaultLogger.WithField(logfields.LogSubsys, "logging").Warningf("invalid logging level provided: %s; setting to %s", levelOpt, DefaultLogLevelStr)
			o[LevelOpt] = DefaultLogLevelStr
			level = LevelStringToLogrusLevel[DefaultLogLevelStr]
		}
	} else {
		// No logging option provided, default to DefaultLogLevelStr.
		o[LevelOpt] = DefaultLogLevelStr
		level = LevelStringToLogrusLevel[DefaultLogLevelStr]
	}
	return level
}

// configureLogLevelFromOptions sets the log level of the DefaultLogger based
// off of the value of LevelOpt in logOpts. If LevelOpt is not set in logOpts,
// it defaults to DefaultLogLevelStr.
func setLogLevelFromOptions(logOpts LogOptions) {
	DefaultLogger.SetLevel(logOpts.configureLogLevelFromOptions())
}

// SetupLogging sets up each logging service provided in loggers and configures
// each logger with the provided logOpts.
func SetupLogging(loggers []string, logOpts map[string]string, tag string, debug bool) error {
	logOptions = logOpts

	// Set default logger to output to stdout if no loggers are provided.
	if len(loggers) == 0 {
		// TODO: switch to a per-logger version when we upgrade to logrus >1.0.3
		logrus.SetOutput(os.Stdout)
	}

	ConfigureLogLevel(debug)

	// always suppress the default logger so libraries don't print things
	logrus.SetLevel(logrus.PanicLevel)

	// Iterate through all provided loggers and configure them according
	// to user-provided settings.
	for _, logger := range loggers {
		switch logger {
		case Syslog:
			valuesToValidate := getLogDriverConfig(Syslog, logOptions)
			err := validateOpts(Syslog, valuesToValidate, syslogOpts)
			if err != nil {
				return err
			}
			setupSyslog(valuesToValidate, tag, debug)
		default:
			return fmt.Errorf("provided log driver %q is not a supported log driver", logger)
		}
	}

	return nil
}

// SetLogLevel sets the log level on DefaultLogger. This logger is, by
// convention, the base logger for package specific ones thus setting the level
// here impacts the default logging behaviour.
// This function is thread-safe when logging, reading DefaultLogger.LevelOpt is
// not protected this way, however.
func SetLogLevel(level logrus.Level) {
	DefaultLogger.SetLevel(level)
}

// ConfigureLogLevel configures the logging level of the global logger. If
// debugging is not enabled, it will set the logging level based off of the
// logging options configured at bootstrap. Debug being enabled takes precedence
// over the configuration in the logging options.
// It is thread-safe.
func ConfigureLogLevel(debug bool) {
	if debug {
		SetLogLevel(logrus.DebugLevel)
	} else {
		setLogLevelFromOptions(logOptions)
	}
}

// setupSyslog sets up and configures syslog with the provided options in
// logOpts. If some options are not provided, sensible defaults are used.
func setupSyslog(logOpts map[string]string, tag string, debug bool) {
	logLevel, ok := logOpts[SLevel]
	if !ok {
		if debug {
			logLevel = "debug"
		} else {
			logLevel = "info"
		}
	}

	//Validate provided log level.
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		DefaultLogger.Fatal(err)
	}

	DefaultLogger.SetLevel(level)
	// Create syslog hook.
	h, err := logrus_syslog.NewSyslogHook("", "", syslogLevelMap[level], tag)
	if err != nil {
		DefaultLogger.Fatal(err)
	}
	// TODO: switch to a per-logger version when we upgrade to logrus >1.0.3
	logrus.AddHook(h)
}

// setupFormatter sets up the text formatting for logs output by logrus.
func setupFormatter() logrus.Formatter {
	fileFormat := new(logrus.TextFormatter)
	fileFormat.DisableTimestamp = true
	fileFormat.DisableColors = true
	switch os.Getenv("INITSYSTEM") {
	case "SYSTEMD":
		fileFormat.FullTimestamp = true
	default:
		fileFormat.TimestampFormat = time.RFC3339
	}

	// TODO: switch to a per-logger version when we upgrade to logrus >1.0.3
	return fileFormat
}

// validateOpts iterates through all of the keys in logOpts, and errors out if
// the key in logOpts is not a key in supportedOpts.
func validateOpts(logDriver string, logOpts map[string]string, supportedOpts map[string]bool) error {
	for k := range logOpts {
		if !supportedOpts[k] {
			return fmt.Errorf("provided configuration value %q is not supported as a logging option for log driver %s", k, logDriver)
		}
	}
	return nil
}

// getLogDriverConfig returns a map containing the key-value pairs that start
// with string logDriver from map logOpts.
func getLogDriverConfig(logDriver string, logOpts map[string]string) map[string]string {
	keysToValidate := make(map[string]string)
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
func MultiLine(logFn func(args ...interface{}), output string) {
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
