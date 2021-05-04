// Copyright 2019 Authors of Cilium
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

// +build !privileged_tests

package logging

import (
	"reflect"
	"testing"

	"github.com/sirupsen/logrus"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type LoggingSuite struct{}

var _ = Suite(&LoggingSuite{})

func (s *LoggingSuite) TestGetLogLevel(c *C) {
	opts := LogOptions{}

	// case doesn't matter with log options
	opts[LevelOpt] = "DeBuG"
	c.Assert(opts.GetLogLevel(), Equals, logrus.DebugLevel)

	opts[LevelOpt] = "Invalid"
	c.Assert(opts.GetLogLevel(), Equals, DefaultLogLevel)
}

func (s *LoggingSuite) TestGetLogFormat(c *C) {
	opts := LogOptions{}

	// case doesn't matter with log options
	opts[FormatOpt] = "JsOn"
	c.Assert(opts.GetLogFormat(), Equals, LogFormatJSON)

	opts[FormatOpt] = "Invalid"
	c.Assert(opts.GetLogFormat(), Equals, DefaultLogFormat)
}

func (s *LoggingSuite) TestSetLogLevel(c *C) {
	oldLevel := DefaultLogger.GetLevel()
	defer DefaultLogger.SetLevel(oldLevel)

	SetLogLevel(logrus.TraceLevel)
	c.Assert(DefaultLogger.GetLevel(), Equals, logrus.TraceLevel)
}

func (s *LoggingSuite) TestSetDefaultLogLevel(c *C) {
	oldLevel := DefaultLogger.GetLevel()
	defer DefaultLogger.SetLevel(oldLevel)

	SetDefaultLogLevel()
	c.Assert(DefaultLogger.GetLevel(), Equals, DefaultLogLevel)
}

func (s *LoggingSuite) TestSetLogFormat(c *C) {
	oldFormatter := DefaultLogger.Formatter
	defer DefaultLogger.SetFormatter(oldFormatter)

	SetLogFormat(LogFormatJSON)
	c.Assert(reflect.TypeOf(DefaultLogger.Formatter).String(), Equals, "*logrus.JSONFormatter")
}

func (s *LoggingSuite) TestSetDefaultLogFormat(c *C) {
	oldFormatter := DefaultLogger.Formatter
	defer DefaultLogger.SetFormatter(oldFormatter)

	SetDefaultLogFormat()
	c.Assert(reflect.TypeOf(DefaultLogger.Formatter).String(), Equals, "*logrus.TextFormatter")
}

func (s *LoggingSuite) TestSetupLogging(c *C) {
	oldLevel := DefaultLogger.GetLevel()
	defer DefaultLogger.SetLevel(oldLevel)

	// Validates that we configure the DefaultLogger correctly
	logOpts := LogOptions{
		"format": "json",
		"level":  "error",
	}

	SetupLogging([]string{}, logOpts, "", false)
	c.Assert(DefaultLogger.GetLevel(), Equals, logrus.ErrorLevel)
	c.Assert(reflect.TypeOf(DefaultLogger.Formatter).String(), Equals, "*logrus.JSONFormatter")

	// Validate that the 'debug' flag/arg overrides the logOptions
	SetupLogging([]string{}, logOpts, "", true)
	c.Assert(DefaultLogger.GetLevel(), Equals, logrus.DebugLevel)
}
