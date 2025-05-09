// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/cilium/cilium/test/config"
	ginkgoext "github.com/cilium/cilium/test/ginkgo-ext"
)

// GetSSHMetadata executes the command in '-cilium.SSHConfig' to fetch the
// SSH configuration for the target VM name 'vmName'.
func GetSSHMetadata(vmName string) ([]byte, error) {
	var stdout, stderr bytes.Buffer
	if config.CiliumTestConfig.SSHConfig == "" {
		return nil, fmt.Errorf("Failed to read -cilium.SSHConfig.")
	}
	cmd := getCmd(config.CiliumTestConfig.SSHConfig)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		ginkgoext.GinkgoPrint("cmd='%s %s'\noutput:\n%s\nstderr:\n%s\n",
			cmd.Path, strings.Join(cmd.Args, " "), stdout.String(), stderr.String())
		return nil, err
	}
	return stdout.Bytes(), nil
}

func getCmd(vmCommand string) *exec.Cmd {
	log.Infof("running command '%v'", vmCommand)
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
