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

import "os/exec"

// sudo returns cmd run with sudo. cmd is modified in place.
func sudo(cmd *exec.Cmd) (*exec.Cmd, error) {
	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		return nil, err
	}
	cmd.Args = append([]string{cmd.Path}, cmd.Args...)
	cmd.Path = sudoPath
	return cmd, nil
}
