// Copyright 2019 Authors of Cilium
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

package netns

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
)

// RemoveIfFromNetNSIfExists removes the given interface from the given
// network namespace.
//
// If the interface does not exist, no error will be returned.
func RemoveIfFromNetNSIfExists(netNS ns.NetNS, ifName string) error {
	return netNS.Do(func(_ ns.NetNS) error {
		l, err := netlink.LinkByName(ifName)
		if err != nil {
			if strings.Contains(err.Error(), "Link not found") {
				return nil
			}
			return err
		}
		return netlink.LinkDel(l)
	})
}

// ReplaceNetNSWithName creates a network namespace with the given name.
// If such netns already exists from a previous run, it will be removed
// and then re-created to avoid any previous state of the netns.
//
// FIXME: replace "ip-netns" invocations with native Go code
func ReplaceNetNSWithName(netNSName string) (ns.NetNS, error) {
	path := netNSPath(netNSName)

	if err := ns.IsNSorErr(path); err == nil {
		if err := exec.Command("ip", "netns", "del", netNSName).Run(); err != nil {
			return nil, fmt.Errorf("Unable to delete named netns %s: %s", netNSName, err)
		}
	}

	if err := exec.Command("ip", "netns", "add", netNSName).Run(); err != nil {
		return nil, fmt.Errorf("Unable to create named netns %s: %s", netNSName, err)
	}

	ns, err := ns.GetNS(path)
	if err != nil {
		return nil, fmt.Errorf("Unable to open netns %s: %s", path, err)
	}

	return ns, nil
}

// RemoveNetNSWithName removes the given named network namespace.
//
// FIXME: replace "ip-netns" invocations with native Go code
func RemoveNetNSWithName(netNSName string) error {
	if err := exec.Command("ip", "netns", "del", netNSName).Run(); err != nil {
		return fmt.Errorf("Unable to delete named netns %s: %s", netNSName, err)
	}

	return nil
}

func netNSPath(name string) string {
	return filepath.Join("/", "var", "run", "netns", name)
}
