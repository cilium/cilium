// Copyright 2019-2020 Authors of Cilium
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

package cmd

import (
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/sysctl"
)

func enableIPForwarding() error {
	if err := sysctl.Enable("net.ipv4.ip_forward"); err != nil {
		return err
	}
	if err := sysctl.Enable("net.ipv4.conf.all.forwarding"); err != nil {
		return err
	}
	if option.Config.EnableIPv6 {
		if err := sysctl.Enable("net.ipv6.conf.all.forwarding"); err != nil {
			return err
		}
	}
	return nil
}
