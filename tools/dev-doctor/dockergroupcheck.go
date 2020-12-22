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
