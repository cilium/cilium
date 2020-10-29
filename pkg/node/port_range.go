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

package node

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/sysctl"
)

// EphemeralPortRange returns the minimal and maximal ports from the ephemeral
// port range.
func EphemeralPortRange() (string, int, int, error) {
	ephemeralPortRangeStr, err := sysctl.Read("net.ipv4.ip_local_port_range")
	if err != nil {
		return "", 0, 0, fmt.Errorf("Unable to read net.ipv4.ip_local_port_range")
	}
	ephemeralPortRange := strings.Split(ephemeralPortRangeStr, "\t")
	if len(ephemeralPortRange) != 2 {
		return "", 0, 0, fmt.Errorf("Invalid ephemeral port range: %s", ephemeralPortRangeStr)
	}
	ephemeralPortMin, err := strconv.Atoi(ephemeralPortRange[0])
	if err != nil {
		return "", 0, 0, fmt.Errorf("Unable to parse min port value %s for ephemeral range", ephemeralPortRange[0])
	}
	ephemeralPortMax, err := strconv.Atoi(ephemeralPortRange[1])
	if err != nil {
		return "", 0, 0, fmt.Errorf("Unable to parse max port value %s for ephemeral range", ephemeralPortRange[1])
	}
	return ephemeralPortRangeStr, ephemeralPortMin, ephemeralPortMax, nil
}
