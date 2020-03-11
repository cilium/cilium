// Copyright 2020 Authors of Cilium
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

package context

import (
	"io"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// Context is a context for commands. It holds a reference to the command
// configuration, a logger and I/O streams.
type Context struct {
	VP  *viper.Viper
	Log *logrus.Entry

	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// New creates a new command Context.
func New() *Context {
	vp := newViper()
	logger := logrus.New()
	if vp.GetBool("debug") {
		logger.SetLevel(logrus.DebugLevel)
	}
	return &Context{
		VP:     vp,
		Log:    logrus.NewEntry(logger),
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
}

func newViper() *viper.Viper {
	vp := viper.New()
	vp.SetEnvPrefix("hubble-proxy")
	vp.SetConfigName(".hubble-proxy") // name of config file (without extension)
	vp.AddConfigPath("$HOME")         // home directory as first search path
	vp.AutomaticEnv()                 // support configuration from environment variables
	return vp
}
