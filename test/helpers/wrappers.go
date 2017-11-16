// Copyright 2017 Authors of Cilium
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

import "fmt"

const (
	TCP_RR = PerfTest("TCP_RR")
	UDP_RR = PerfTest("UDP_RR")
)

// Ping returns the string representing the ping command to ping the specified
// endpoint.
func Ping(endpoint string) string {
	return fmt.Sprintf("ping -c %d %s", PingCount, endpoint)
}

// Ping6 returns the string representing the ping6 command to ping6 the
// specified endpoint.
func Ping6(endpoint string) string {
	return fmt.Sprintf("ping6  -c %d %s", PingCount, endpoint)
}

// Curl returns the string representing the curl command with `-s` and `--fail`
// options enabled to curl the specified endpoint.
func CurlFail(endpoint string) string {
	return fmt.Sprintf("curl -s --fail --connect-timeout %d %s", CurlConnectTimeout, endpoint)
}

type PerfTest string

// Netperf returns the string representing the netperf command to use when testing
// connectivity between endpoints.
func Netperf(endpoint string, perfTest PerfTest) string {
	return fmt.Sprintf("netperf -l 3 -t %s -H %s", perfTest, endpoint)
}
