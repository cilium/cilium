// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/onsi/ginkgo"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/test/config"
	ginkgoext "github.com/cilium/cilium/test/ginkgo-ext"
)

// CreateVM creates a new vagrant server.Receives a scope which indicates the
// target server that needs to be created. In case of any error on vagrant
// [provision|up|ssh-config] error will be returned.
func CreateVM(scope string) error {
	createCMD := "vagrant up %s --provision"

	for _, v := range Status(scope) {
		switch v {
		case "running":
			createCMD = "vagrant provision %s"
		case "not_created":
			createCMD = "vagrant up %s --provision"
		default:
			// Sometimes servers are stoped and not destroyed. Destroy VM just in case
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

	globalWriter := ginkgoext.NewWriter(ginkgo.GinkgoWriter)

	go io.Copy(globalWriter, stderr)
	go io.Copy(globalWriter, stdout)

	if err := cmd.Start(); err != nil {
		log.WithFields(logrus.Fields{
			"command": createCMD,
			"err":     err,
		}).Fatalf("Create error on start")
		return err
	}
	result := cmd.Wait()
	io.Copy(ginkgoext.GinkgoWriter, globalWriter.Buffer)
	return result
}

// GetVagrantSSHMetadata returns a string containing the output of `vagrant ssh-config`
// for the provided Vagrant of name vmName. Returns an error if
// `vagrant ssh-config` fails to execute.
func GetVagrantSSHMetadata(vmName string) ([]byte, error) {
	// debugVMs is used when ssh-config returns error and be able to debug the
	// virtual machines status.
	debugVms := func() {
		cmd := getCmd("vagrant status --machine-readable")
		output, _ := cmd.CombinedOutput()
		ginkgoext.Failf("Vagrant status on failure:\n%s\n", output)
	}

	var stdout, stderr bytes.Buffer
	cmd := getCmd(fmt.Sprintf("vagrant ssh-config %s", vmName))
	if config.CiliumTestConfig.SSHConfig != "" {
		cmd = getCmd(config.CiliumTestConfig.SSHConfig)
		debugVms = func() {} // not apply the debug helper due is a dev env.
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		ginkgoext.GinkgoPrint("cmd='%s %s'\noutput:\n%s\nstderr:\n%s\n",
			cmd.Path, strings.Join(cmd.Args, " "), stdout.String(), stderr.String())
		debugVms()
		return nil, err
	}
	return stdout.Bytes(), nil
}

// DestroyVM destroys all running Vagrant VMs in the provided scope. It returns an
// error if deletion of either the VMs fails
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
	log.Infof("Vagrant: running command '%v'", vmCommand)
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

// Status returns a mapping of Vagrant VM name to its status
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
