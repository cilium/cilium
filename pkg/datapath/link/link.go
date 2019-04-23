// Copyright 2016-2017 Authors of Cilium
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

package link

import (
	"fmt"

	"github.com/jsimonetti/rtnetlink"
)

// DeleteByName deletes the interface with the name ifName.
func DeleteByName(ifName string) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("failed to open rtnetlink socket: %v", err)
	}
	defer conn.Close()

	links, err := conn.Link.List()
	if err != nil {
		return fmt.Errorf("failed to lookup links: %v", err)
	}

	for _, link := range links {
		if link.Attributes.Name == ifName {
			return conn.Link.Delete(link.Index)
		}
	}

	return fmt.Errorf("failed to find link %s", ifName)
}

// Rename renames a network link
func Rename(curName, newName string) error {
	conn, err := rtnetlink.Dial(nil)
	if err != nil {
		return fmt.Errorf("failed to open rtnetlink socket: %v", err)
	}
	defer conn.Close()

	links, err := conn.Link.List()
	if err != nil {
		return fmt.Errorf("failed to lookup links: %v", err)
	}

	for _, link := range links {
		if link.Attributes.Name == curName {
			link.Attributes.Name = newName
			return conn.Link.Set(&link)
		}
	}

	return fmt.Errorf("failed to lookup %s", curName)
}
