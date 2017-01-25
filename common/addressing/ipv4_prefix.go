//
// Copyright 2016 Authors of Cilium
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
//
package addressing

import (
	"fmt"
	"time"
)

const (
	ipv4PrefixTimeout = time.Duration(2 * time.Hour)
)

type NodeIPv4Prefix struct {
	NodeAddr     string    `json:"node-address"`
	IPv4         string    `json:"ipv4"`
	ID           uint8     `json:"id"`
	LastTimeSeen time.Time `json:"last-time-seen"`
}

func (n *NodeIPv4Prefix) IsValid() bool {
	return n.LastTimeSeen.Add(ipv4PrefixTimeout).After(time.Now())
}

func (n *NodeIPv4Prefix) SetInvalid() {
	n.LastTimeSeen = time.Unix(0, 0)
}

func (n NodeIPv4Prefix) String() string {
	return n.IPv4 + " => " + n.LastTimeSeen.String()
}

func (n *NodeIPv4Prefix) SetID(id uint8) {
	n.ID = id
	n.IPv4 = fmt.Sprintf(DefaultIPv4Prefix, id)
	n.RefreshLastTimeSeen()
}

func (n *NodeIPv4Prefix) RefreshLastTimeSeen() {
	n.LastTimeSeen = time.Now()
}
