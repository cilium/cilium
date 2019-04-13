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

// PerfTest represents a type of test to run when running `netperf`.
type PerfTest string

const (
	// TCP_RR represents a netperf test for TCP Request/Response performance.
	// For more information, consult : http://www.cs.kent.edu/~farrell/dist/ref/Netperf.html
	TCP_RR = PerfTest("TCP_RR")

	// UDP_RR represents a netperf test for UDP Request/Response performance.
	// For more information, consult : http://www.cs.kent.edu/~farrell/dist/ref/Netperf.html
	UDP_RR = PerfTest("UDP_RR")
)

// Ping returns the string representing the ping command to ping the specified
// endpoint.
func Ping(endpoint string) string {
	return fmt.Sprintf("ping -W 2 -c %d %s", PingCount, endpoint)
}

// Ping6 returns the string representing the ping6 command to ping6 the
// specified endpoint.
func Ping6(endpoint string) string {
	return fmt.Sprintf("ping6 -c %d %s", PingCount, endpoint)
}

// CurlFail returns the string representing the curl command with `-s` and
// `--fail` options enabled to curl the specified endpoint.  It takes a
// variadic optinalValues argument. This is passed on to fmt.Sprintf() and uses
// into the curl message
func CurlFail(endpoint string, optionalValues ...interface{}) string {
	statsInfo := `time-> DNS: '%{time_namelookup}(%{remote_ip})', Connect: '%{time_connect}',` +
		`Transfer '%{time_starttransfer}', total '%{time_total}'`

	if len(optionalValues) > 0 {
		endpoint = fmt.Sprintf(endpoint, optionalValues...)
	}
	return fmt.Sprintf(
		`curl --path-as-is -s -D /dev/stderr --fail --connect-timeout %[1]d --max-time %[2]d %[3]s -w "%[4]s"`,
		CurlConnectTimeout, CurlMaxTimeout, endpoint, statsInfo)
}

// CurlWithHTTPCode retunrs the string representation of the curl command which
// only outputs the HTTP code returned by its execution against the specified
// endpoint. It takes a variadic optinalValues argument. This is passed on to
// fmt.Sprintf() and uses into the curl message
func CurlWithHTTPCode(endpoint string, optionalValues ...interface{}) string {
	if len(optionalValues) > 0 {
		endpoint = fmt.Sprintf(endpoint, optionalValues...)
	}

	return fmt.Sprintf(
		`curl --path-as-is -s  -D /dev/stderr --output /dev/stderr -w '%%{http_code}' --connect-timeout %d %s`,
		CurlConnectTimeout, endpoint)
}

// Netperf returns the string representing the netperf command to use when testing
// connectivity between endpoints.
func Netperf(endpoint string, perfTest PerfTest) string {
	return fmt.Sprintf("netperf -l 3 -t %s -H %s", perfTest, endpoint)
}

// Netcat returns the string representing the netcat command to the specified
// endpoint. It takes a variadic optionalValues arguments, This is passed to
// fmt.Sprintf uses in the netcat message
func Netcat(endpoint string, optionalValues ...interface{}) string {
	if len(optionalValues) > 0 {
		endpoint = fmt.Sprintf(endpoint, optionalValues...)
	}
	return fmt.Sprintf("nc -w 4 %s", endpoint)
}
