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
	lvl, ok := opts.GetLogLevel()
	c.Assert(ok, Equals, true)
	c.Assert(lvl, Equals, logrus.DebugLevel)

	opts[LevelOpt] = "Invalid"
	_, ok = opts.GetLogLevel()
	c.Assert(ok, Equals, false)
}

func (s *LoggingSuite) TestConfigureLogLevelFromOptions(c *C) {
	opts := LogOptions{}

	// corresponding logrus level correctly returned
	opts[LevelOpt] = "panic"
	lvl := opts.configureLogLevelFromOptions()
	c.Assert(lvl, Equals, logrus.PanicLevel)

	// invalid level gets set to default value
	opts[LevelOpt] = "invalid"
	lvl = opts.configureLogLevelFromOptions()
	c.Assert(lvl, Equals, LevelStringToLogrusLevel[DefaultLogLevelStr])

	// no LogOpt provided returns default value and updates the map.
	delete(opts, LevelOpt)
	lvl = opts.configureLogLevelFromOptions()
	c.Assert(lvl, Equals, LevelStringToLogrusLevel[DefaultLogLevelStr])
	lvl, ok := opts.GetLogLevel()
	c.Assert(ok, Equals, true)
	c.Assert(lvl, Equals, LevelStringToLogrusLevel[DefaultLogLevelStr])

}

func (s *LoggingSuite) TestConfigureLogLevelGlobal(c *C) {
	oldLevel := DefaultLogger.GetLevel()

	// The joys of globals...
	defer DefaultLogger.SetLevel(oldLevel)

	ConfigureLogLevel(true)
	lvl := DefaultLogger.GetLevel()
	c.Assert(lvl, Equals, logrus.DebugLevel)

	ConfigureLogLevel(false)
	lvl = DefaultLogger.GetLevel()
	c.Assert(lvl, Equals, LevelStringToLogrusLevel[DefaultLogLevelStr])

}
