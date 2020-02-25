// Copyright 2019 Authors of Hubble
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

package api

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// GetGroupIDByName returns the group ID for the given grpName.
func GetGroupIDByName(grpName string) (int, error) {
	f, err := os.Open(GroupFilePath)
	if err != nil {
		return -1, err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	for {
		s, err := br.ReadString('\n')
		if err == io.EOF {
			break
		}
		if err != nil {
			return -1, err
		}
		p := strings.Split(s, ":")
		if len(p) >= 3 && p[0] == grpName {
			return strconv.Atoi(p[2])
		}
	}
	return -1, fmt.Errorf("group %q not found", grpName)
}

// SetDefaultPermissions sets the given socket to with cilium's default
// group and mode permissions. Group `HubbleGroupName` and mode `0660`
func SetDefaultPermissions(socketPath string) error {
	group := getGroupName()
	gid, err := GetGroupIDByName(group)
	if err != nil {
		return fmt.Errorf("group %s not found", group)
	}

	if err := os.Chown(socketPath, 0, gid); err != nil {
		return fmt.Errorf("failed while setting up %s's group ID"+
			" in %q: %s", group, socketPath, err)
	}

	if err := os.Chmod(socketPath, SocketFileMode); err != nil {
		return fmt.Errorf("failed while setting up %s's file"+
			" permissions in %q: %s", group, socketPath, err)
	}

	return nil
}

func getGroupName() string {
	if name, ok := os.LookupEnv(HubbleGroupNameKey); ok {
		return name
	}
	return HubbleGroupName
}

// GetDefaultSocketPath returns the default server for status and observe command.
func GetDefaultSocketPath() string {
	if path, ok := os.LookupEnv(DefaultSocketPathKey); ok {
		return path
	}
	return DefaultSocketPath
}
