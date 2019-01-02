// Copyright 2018 Authors of Cilium
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

package helpers

import (
	"fmt"

	"github.com/cilium/cilium/test/ginkgo-ext"
)

func (s *SSHMeta) superNetperfRRIPv4(client string, server string, num int) *CmdRes {
	var res *CmdRes

	serverNet, _ := s.ContainerInspectNet(server)
	serverIpv4 := serverNet[IPv4]
	ginkgoext.By("super_netperf to %s from %s (should succeed)", server, client)
	cmd := fmt.Sprintf("super_netperf %d -t TCP_RR -H %s", num, serverIpv4)
	res = s.ContainerExec(client, cmd)
	res.ExpectSuccess("failed: %s", cmd)
	return res
}

// SuperNetperfRR launches 'num' parallel netperf TCP_RR
// (request/response) tests from client to server.
func (s *SSHMeta) SuperNetperfRR(client string, server string, num int) *CmdRes {
	return s.superNetperfRRIPv4(client, server, num)
}

func (s *SSHMeta) superNetperfStreamIPv4(client string, server string, num int) *CmdRes {
	var res *CmdRes

	serverNet, _ := s.ContainerInspectNet(server)
	serverIpv4 := serverNet[IPv4]
	ginkgoext.By("super_netperf to %s from %s (should succeed)", server, client)
	cmd := fmt.Sprintf("super_netperf %d -f g -t TCP_STREAM -H %s", num, serverIpv4)
	res = s.ContainerExec(client, cmd)
	res.ExpectSuccess("failed: %s", cmd)
	return res
}

// SuperNetperfStream launches 'num' parallel netperf TCP_STREAM
// tests from client to server.
func (s *SSHMeta) SuperNetperfStream(client string, server string, num int) *CmdRes {
	return s.superNetperfStreamIPv4(client, server, num)
}
