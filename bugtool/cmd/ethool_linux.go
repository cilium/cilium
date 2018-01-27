// Copyright 2017-2018 Authors of Cilium
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

// +build linux

package cmd

import (
	"fmt"

	"github.com/vishvananda/netlink"
)

func ethoolCommands() []string {
	sources := []string{}
	// Append ethtool links
	if links, err := netlink.LinkList(); err == nil {
		for _, link := range links {
			// query current settings
			sources = append(sources, fmt.Sprintf("ethtool %s", link.Attrs().Name))
			// query for driver information
			sources = append(sources, fmt.Sprintf("ethtool -i %s", link.Attrs().Name))
		}
	}

	return sources
}
