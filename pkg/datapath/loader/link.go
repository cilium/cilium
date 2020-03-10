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

package loader

import (
	"fmt"
	"os/exec"

	"github.com/cilium/cilium/pkg/option"

	"golang.org/x/sys/unix"
)

func SetXDPMode(mode string) error {
	switch mode {
	case option.XDPModeNative:
		if option.Config.XDPMode == option.XDPModeLinkNone ||
			option.Config.XDPMode == option.XDPModeLinkDriver {
			option.Config.XDPMode = option.XDPModeLinkDriver
		} else {
			return fmt.Errorf("XDP Mode conflict: current mode is %s, trying to set conflicting %s",
				option.Config.XDPMode, option.XDPModeLinkDriver)
		}
	case option.XDPModeGeneric:
		if option.Config.XDPMode == option.XDPModeLinkNone ||
			option.Config.XDPMode == option.XDPModeLinkGeneric {
			option.Config.XDPMode = option.XDPModeLinkGeneric
		} else {
			return fmt.Errorf("XDP Mode conflict: current mode is %s, trying to set conflicting %s",
				option.Config.XDPMode, option.XDPModeLinkGeneric)
		}
	case option.XDPModeNone:
		break
	}
	return nil
}

// ProbeXDP checks whether a given XDP mode is supported for the specified device
func ProbeXDP(device, mode string) error {
	cmd := exec.Command("ip", "-force", "link", "set", "dev", device, mode, "off")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("Cannot run ip command: %v", err)
	}
	if err := cmd.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if status, ok := exiterr.Sys().(unix.WaitStatus); ok {
				switch status.ExitStatus() {
				case 2:
					return fmt.Errorf("Mode %s not supported on device %s", mode, device)
				default:
					return fmt.Errorf("XDP not supported on OS")
				}
			}
		} else {
			return fmt.Errorf("Cannot wait for ip command: %v", err)
		}
	}
	return nil
}
