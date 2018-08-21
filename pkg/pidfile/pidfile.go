// Copyright 2017 Authors of Cilium
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

package pidfile

import (
	"io/ioutil"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/cilium/pkg/logging"
)

var log = logging.DefaultLogger

// Write the pid of the process to the specified path, and attach a cleanup
// handler to the exit of the program so it's removed afterwards.
func Write(path string) error {
	pid := os.Getpid()
	pidBytes := []byte(strconv.Itoa(pid) + "\n")
	if err := ioutil.WriteFile(path, pidBytes, 0660); err != nil {
		return err
	}

	// Handle the cleanup
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)
	go func() {
		for s := range sig {
			log.WithField("signal", s).Info("Exiting due to signal")
			os.Remove(path)
			os.Exit(0)
		}
	}()

	return nil
}
