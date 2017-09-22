// Copyright 2016-2017 Authors of Cilium
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

package common

import (
	"fmt"
	"log/syslog"
	"net"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/evalphobia/logrus_fluent"
	"github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
)

const (
	fAddr  = "fluentd.address"
	fTag   = "fluentd.tag"
	fLevel = "fluentd.level"

	SLevel = "syslog.level"

	lAddr     = "logstash.address"
	lLevel    = "logstash.level"
	lProtocol = "logstash.protocol"

	Syslog   = "syslog"
	Fluentd  = "fluentd"
	Logstash = "logstash"
)

// syslogOpts is the set of supported options for syslog configuration.
var syslogOpts = map[string]bool{
	"syslog.level": true,
}

// fluentDOpts is the set of supported options for fluentD configuration.
var fluentDOpts = map[string]bool{
	fAddr:  true,
	fTag:   true,
	fLevel: true,
}

// logstashOpts is the set of supported options for logstash configuration.
var logstashOpts = map[string]bool{
	lAddr:     true,
	lLevel:    true,
	lProtocol: true,
}

// syslogLevelMap maps logrus.Level values to syslog.Priority levels.
var syslogLevelMap = map[logrus.Level]syslog.Priority{
	logrus.PanicLevel: syslog.LOG_ALERT,
	logrus.FatalLevel: syslog.LOG_CRIT,
	logrus.ErrorLevel: syslog.LOG_ERR,
	logrus.WarnLevel:  syslog.LOG_WARNING,
	logrus.InfoLevel:  syslog.LOG_INFO,
	logrus.DebugLevel: syslog.LOG_DEBUG,
}

// setFireLevels returns a slice of logrus.Level values higher in priority
// and including level, excluding any levels lower in priority.
func setFireLevels(level logrus.Level) []logrus.Level {
	switch level {
	case logrus.PanicLevel:
		return []logrus.Level{logrus.PanicLevel}
	case logrus.FatalLevel:
		return []logrus.Level{logrus.PanicLevel, logrus.FatalLevel}
	case logrus.ErrorLevel:
		return []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel}
	case logrus.WarnLevel:
		return []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel, logrus.WarnLevel}
	case logrus.InfoLevel:
		return []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel, logrus.WarnLevel, logrus.InfoLevel}
	case logrus.DebugLevel:
		return []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel, logrus.WarnLevel, logrus.InfoLevel, logrus.DebugLevel}
	default:
		logrus.Infof("logrus level %v is not supported at this time; defaulting to info level", level)
		return []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel, logrus.WarnLevel, logrus.InfoLevel}
	}
}

// SetupLogging sets up each logging service provided in loggers and configures
// each logger with the provided logOpts.
func SetupLogging(loggers []string, logOpts map[string]string, tag string, debug bool) error {
	// FIXME: Disabled for now
	//setupFormatter()

	// Set default logger to output to stdout if no loggers are provided.
	if len(loggers) == 0 {
		logrus.SetOutput(os.Stdout)
	}

	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}

	// Iterate through all provided loggers and configure them according
	// to user-provided settings.
	for _, logger := range loggers {
		valuesToValidate := getLogDriverConfig(logger, logOpts)
		switch logger {
		case Syslog:
			valuesToValidate := getLogDriverConfig(Syslog, logOpts)
			err := validateOpts(Syslog, valuesToValidate, syslogOpts)
			if err != nil {
				return err
			}
			setupSyslog(valuesToValidate, tag, debug)
		case Fluentd:
			err := validateOpts(logger, valuesToValidate, fluentDOpts)
			if err != nil {
				return err
			}
			setupFluentD(valuesToValidate, debug)
			//TODO - need to finish logstash integration.
		/*case Logstash:
		fmt.Printf("SetupLogging: in logstash case\n")
		err := validateOpts(logger, valuesToValidate, logstashOpts)
		fmt.Printf("SetupLogging: validating options for logstash complete\n")
		if err != nil {
			fmt.Printf("SetupLogging: error validating logstash opts %v\n", err.Error())
			return err
		}
		fmt.Printf("SetupLogging: about to setup logstash\n")
		setupLogstash(valuesToValidate)
		*/
		default:
			return fmt.Errorf("provided log driver %q is not a supported log driver", logger)
		}
	}
	return nil
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
		logrus.Fatal(err)
	}

	logrus.SetLevel(level)
	// Create syslog hook.
	h, err := logrus_syslog.NewSyslogHook("", "", syslogLevelMap[level], tag)
	if err != nil {
		logrus.Fatal(err)
	}
	logrus.AddHook(h)
}

// setupFormatter sets up the text formatting for logs output by logrus.
func setupFormatter() {
	fileFormat := new(logrus.TextFormatter)
	fileFormat.DisableColors = true
	switch os.Getenv("INITSYSTEM") {
	case "SYSTEMD":
		fileFormat.DisableTimestamp = true
		fileFormat.FullTimestamp = true
	default:
		fileFormat.TimestampFormat = time.RFC3339
	}
	logrus.SetFormatter(fileFormat)
}

// setupFluentD sets up and configures FluentD with the provided options in
// logOpts. If some options are not provided, sensible defaults are used.
func setupFluentD(logOpts map[string]string, debug bool) {
	//If no logging level set for fluentd, use debug value if it is set.
	// Logging level set for fluentd takes precedence over debug flag
	// fluent.level provided.
	logLevel, ok := logOpts[fLevel]
	if !ok {
		if debug {
			logLevel = "debug"
		} else {
			logLevel = "info"
		}
	}
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		logrus.Fatal(err)
	}

	hostAndPort, ok := logOpts[fAddr]
	if !ok {
		hostAndPort = "localhost:24224"
	}

	host, strPort, err := net.SplitHostPort(hostAndPort)
	if err != nil {
		logrus.Fatal(err)
	}
	port, err := strconv.Atoi(strPort)
	if err != nil {
		logrus.Fatal(err)
	}

	h, err := logrus_fluent.New(host, port)
	if err != nil {
		logrus.Fatal(err)
	}

	tag, ok := logOpts[fTag]
	if ok {
		h.SetTag(tag)
	}

	// set custom fire level
	h.SetLevels(setFireLevels(level))
	logrus.AddHook(h)
}

// setupLogstash sets up and configures Logstash with the provided options in
// logOpts. If some options are not provided, sensible defaults are used.
/// FIXME GH-1578 - needs to be tested with a working logstash setup.
//func setupLogstash(logOpts map[string]string) {
//	hostAndPort, ok := logOpts[lAddr]
//	if !ok {
//		hostAndPort = "172.17.0.2:999"
//	}
//
//	protocol, ok := logOpts[lProtocol]
//	if !ok {
//		protocol = "tcp"
//	}
//
//	h, err := logrustash.NewHook(protocol, hostAndPort, "cilium")
//	if err != nil {
//		logrus.Fatal(err)
//	}
//
//	logrus.AddHook(h)
//}

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
			logrus.Fatal(err)
		}
		if ok {
			keysToValidate[k] = v
		}
	}
	return keysToValidate
}
