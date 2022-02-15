// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os/user"
	"runtime"
)

// A dockerGroupCheck checks that the current user is in the docker group.
type dockerGroupCheck struct{}

func (dockerGroupCheck) Name() string {
	return "docker-group"
}

func (dockerGroupCheck) Run() (checkResult, string) {
	if runtime.GOOS != "linux" {
		return checkSkipped, "docker group only used on linux"
	}

	currentUser, err := user.Current()
	if err != nil {
		return checkFailed, err.Error()
	}

	groupIDs, err := currentUser.GroupIds()
	if err != nil {
		return checkFailed, err.Error()
	}

	dockerGroup, err := user.LookupGroup("docker")
	if err != nil {
		return checkFailed, err.Error()
	}

	for _, groupID := range groupIDs {
		if groupID == dockerGroup.Gid {
			return checkOK, fmt.Sprintf("user %s in docker group", currentUser.Username)
		}
	}

	return checkError, fmt.Sprintf("user %s not in docker group", currentUser.Username)
}

func (dockerGroupCheck) Hint() string {
	return `Run "sudo usermod $USER --append --group docker", then log out and back in.`
}
