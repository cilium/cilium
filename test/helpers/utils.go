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

package helpers

import (
	"bytes"
	"fmt"
	"html/template"
	"io/ioutil"
	"os"
	"syscall"
	"time"

	"github.com/cilium/cilium/test/config"
	"github.com/onsi/ginkgo"
	log "github.com/sirupsen/logrus"
)

//IsRunningOnJenkins detects if the current Ginkgo application is running in
//Jenkins. Returns true if yes.
func IsRunningOnJenkins() bool {
	result := true

	env := []string{"JENKINS_HOME", "NODE_NAME"}

	for _, varName := range env {
		if val := os.Getenv(varName); val == "" {
			result = false
			log.Infof("Variable '%s' is not present, it is not running on jenkins", varName)
		}
	}
	return result
}

//Sleep sleeps for the specified duration in seconds
func Sleep(delay time.Duration) {
	time.Sleep(delay * time.Second)
}

//CountValues filters data based on the specified key. Returns the number of
//matches in data for key and the length of data.
func CountValues(key string, data []string) (int, int) {
	var result int

	for _, x := range data {
		if x == key {
			result++
		}
	}
	return result, len(data)
}

//RenderTemplateToFile renders a text/template string into a target filename with specific persmision.
// It will return an error if the template can't be validated or can't write the file
func RenderTemplateToFile(filename string, tmplt string, perm os.FileMode) error {
	t, err := template.New("").Parse(tmplt)
	if err != nil {
		return err
	}
	content := new(bytes.Buffer)
	err = t.Execute(content, nil)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(filename, content.Bytes(), perm)
	if err != nil {
		return err
	}
	return nil
}

//TimeoutConfig represents the configuration for the timeout of a command.
type TimeoutConfig struct {
	Ticker  time.Duration // Check interval in duration.
	Timeout time.Duration // Timeout definition
}

//WithTimeout executes function body using the interval specified in config
//until the timeout in config is reached. Returns an error if the timeout is
//exceeded for body to execute successfully.
func WithTimeout(body func() bool, msg string, config *TimeoutConfig) error {
	if config.Ticker == 0 {
		config.Ticker = 5
	}

	done := time.After(config.Timeout * time.Second)
	ticker := time.NewTicker(config.Ticker * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if body() {
				return nil
			}
		case <-done:
			return fmt.Errorf("Timeout reached: %s", msg)
		}
	}
}

// Fail is a Ginkgo failure handler which raises a SIGSTOP for the test process
// when there is a failure, so that developers can debug the live environment.
// It is only triggered if the developer provides a commandline flag.
func Fail(description string, callerSkip ...int) {
	if len(callerSkip) > 0 {
		callerSkip[0]++
	} else {
		callerSkip = []int{1}
	}

	if config.CiliumTestConfig.HoldEnvironment {
		test := ginkgo.CurrentGinkgoTestDescription()
		pid := syscall.Getpid()

		fmt.Fprintf(os.Stdout, "\n---\n%s", test.FullTestText)
		fmt.Fprintf(os.Stdout, "\nat %s:%d", test.FileName, test.LineNumber)
		fmt.Fprintf(os.Stdout, "\n\n%s", description)
		fmt.Fprintf(os.Stdout, "\n\nPausing test for debug, use vagrant to access test setup.")
		fmt.Fprintf(os.Stdout, "\nRun \"kill -SIGCONT %d\" to continue.\n", pid)
		syscall.Kill(pid, syscall.SIGSTOP)
	}
	ginkgo.Fail(description, callerSkip...)
}
