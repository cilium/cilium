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
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

//Create a new vagrant server. Receives and scope that it's the target server that need to be created.
// In case of any error on vagrant [provision|up|ssh-config] error will be returned.
func CreateVM(scope string) error {
	createCMD := "vagrant up %s --provision"

	for _, v := range Status(scope) {
		switch v {
		case "running":
			createCMD = "vagrant provision %s"
		case "not_created":
			createCMD = "vagrant up %s --provision"
		default:
			//Sometimes server are stoped and not destroyed. DestroyVM just in case
			DestroyVM(scope)
		}
	}
	createCMD = fmt.Sprintf(createCMD, scope)
	log.Infof("Vagrant:Create: running '%s'", createCMD)
	cmd := getCmd(createCMD)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("error getting stdout: %s", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("error getting stderr: %s", err)
	}

	go func() {
		in := bufio.NewScanner(stdout)
		for in.Scan() {
			log.Infof("stdout: %s", in.Text()) // write each line to your log
		}
	}()

	go func() {
		errIn := bufio.NewScanner(stderr)
		for errIn.Scan() {
			log.Infof("stderr: %s", errIn.Text())
		}
	}()

	if err := cmd.Start(); err != nil {
		log.WithFields(logrus.Fields{
			"command": createCMD,
			"err":     err,
		}).Fatalf("Create error on start")
		return err
	}

	if err := cmd.Wait(); err != nil {
		return err
	}

	return nil
}

// GetVagrantSSHMetadata returns a string containing the output of `vagrant ssh-config`
// for the provided Vagrant of name vmName. Returns an error if
// `vagrant ssh-config` fails to execute.
func GetVagrantSSHMetadata(vmName string) ([]byte, error) {
	cmd := getCmd(fmt.Sprintf("vagrant ssh-config %s", vmName))
	result, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return result, nil
}

//DestroyVM destroys all running Vagrant VMs in the provided scope. It returns an
//error if deletion of either the VMs fails
func DestroyVM(scope string) error {
	command := fmt.Sprintf("vagrant destroy -f %s ", scope)
	cmd := getCmd(command)
	_, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	return nil
}

func getCmd(vmCommand string) *exec.Cmd {
	log.Infof("Vagrant: running command %q", vmCommand)
	cmd := exec.Command(getPath("bash"), "-c", vmCommand)
	cmd.Dir = getDir()
	return cmd
}

func getDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return "/tmp/"
	}
	return fmt.Sprintf("%s/", dir)
}

func getPath(prog string) string {
	path, err := exec.LookPath(prog)
	if err != nil {
		return ""
	}
	return path
}

//Status returns a mapping of Vagrant VM name to its status
func Status(key string) map[string]string {
	result := map[string]string{}

	cmd := getCmd(fmt.Sprintf("vagrant status %s --machine-readable", key))
	data, err := cmd.CombinedOutput()
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(data), "\n") {
		val := strings.Split(line, ",")
		if len(val) > 2 && val[2] == "state" {
			result[val[1]] = val[3]
		}
	}
	return result
}
