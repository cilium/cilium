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

import (
	"fmt"
	"net"
	"strings"
)

// PerfTest represents a type of test to run when running `netperf`.
type PerfTest string

const (
	// TCP_RR represents a netperf test for TCP Request/Response performance.
	// For more information, consult : http://www.cs.kent.edu/~farrell/dist/ref/Netperf.html
	TCP_RR = PerfTest("TCP_RR")

	// TCP_STREAM represents a netperf test for TCP throughput performance.
	// For more information, consult : http://www.cs.kent.edu/~farrell/dist/ref/Netperf.html
	TCP_STREAM = PerfTest("TCP_STREAM")

	// TCP_MAERTS represents a netperf test for TCP throughput performance (reverse direction of TCP_STREAM).
	// For more information, consult : http://www.cs.kent.edu/~farrell/dist/ref/Netperf.html
	TCP_MAERTS = PerfTest("TCP_MAERTS")

	// TCP_CRR represents a netperf test that connects and sends single request/response
	// For more information, consult : http://www.cs.kent.edu/~farrell/dist/ref/Netperf.html
	TCP_CRR = PerfTest("TCP_CRR")

	// UDP_RR represents a netperf test for UDP Request/Response performance.
	// For more information, consult : http://www.cs.kent.edu/~farrell/dist/ref/Netperf.html
	UDP_RR = PerfTest("UDP_RR")
)

// PingWithCount returns the string representing the ping command to ping the
// specified endpoint, and takes a custom number of requests to send.
func PingWithCount(endpoint string, count uint) string {
	return fmt.Sprintf("ping -W %d -c %d %s", PingTimeout, count, endpoint)
}

// Ping returns the string representing the ping command to ping the specified
// endpoint.
func Ping(endpoint string) string {
	return PingWithCount(endpoint, PingCount)
}

// Ping6 returns the string representing the ping6 command to ping6 the
// specified endpoint.
func Ping6(endpoint string) string {
	return fmt.Sprintf("ping6 -c %d %s", PingCount, endpoint)
}

// Wrk runs a standard wrk test for http
func Wrk(endpoint string) string {
	return fmt.Sprintf("wrk -t2 -c100 -d30s -R2000 http://%s", endpoint)
}

// CurlFail returns the string representing the curl command with `-s` and
// `--fail` options enabled to curl the specified endpoint.  It takes a
// variadic optionalValues argument. This is passed on to fmt.Sprintf() and
// used into the curl message.
func CurlFail(endpoint string, optionalValues ...interface{}) string {
	statsInfo := `time-> DNS: '%{time_namelookup}(%{remote_ip})', Connect: '%{time_connect}',` +
		`Transfer '%{time_starttransfer}', total '%{time_total}'`

	if len(optionalValues) > 0 {
		endpoint = fmt.Sprintf(endpoint, optionalValues...)
	}
	return fmt.Sprintf(
		`curl --path-as-is -s -D /dev/stderr --fail --connect-timeout %d --max-time %d %s -w "%s"`,
		CurlConnectTimeout, CurlMaxTimeout, endpoint, statsInfo)
}

// CurlFailNoStats does the same as CurlFail() except that it does not print
// the stats info.
func CurlFailNoStats(endpoint string, optionalValues ...interface{}) string {
	if len(optionalValues) > 0 {
		endpoint = fmt.Sprintf(endpoint, optionalValues...)
	}
	return fmt.Sprintf(
		`curl --path-as-is -s -D /dev/stderr --fail --connect-timeout %[1]d --max-time %[2]d %[3]s`,
		CurlConnectTimeout, CurlMaxTimeout, endpoint)
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

// CurlWithRetries returns the string representation of the curl command that
// retries the request if transient problems occur. The parameter "retries"
// indicates the maximum number of attempts.  If flag "fail" is true, the
// function will call CurlFail() and add --retry flag at the end of the command
// and return.  If flag "fail" is false, the function will generate the command
// with --retry flag and return.
func CurlWithRetries(endpoint string, retries int, fail bool, optionalValues ...interface{}) string {
	if fail {
		return fmt.Sprintf(
			`%s --retry %d`,
			CurlFail(endpoint, optionalValues...), retries)
	}
	if len(optionalValues) > 0 {
		endpoint = fmt.Sprintf(endpoint, optionalValues...)
	}
	return fmt.Sprintf(
		`curl --path-as-is -s  -D /dev/stderr --output /dev/stderr --retry %d %s`,
		retries, endpoint)
}

// Netperf returns the string representing the netperf command to use when testing
// connectivity between endpoints.
func Netperf(endpoint string, perfTest PerfTest, options string) string {
	return fmt.Sprintf("netperf -l 3 -t %s -H %s %s", perfTest, endpoint, options)
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

// PythonBind returns the string representing a python3 command which will try
// to bind a socket on the given address and port. Python is available in the
// log-gatherer pod.
func PythonBind(addr string, port uint16, proto string) string {
	var opts []string
	if strings.Contains(addr, ":") {
		opts = append(opts, "family=socket.AF_INET6")
	} else {
		opts = append(opts, "family=socket.AF_INET")
	}

	switch strings.ToLower(proto) {
	case "tcp":
		opts = append(opts, "type=socket.SOCK_STREAM")
	case "udp":
		opts = append(opts, "type=socket.SOCK_DGRAM")
	}

	return fmt.Sprintf(
		`/usr/bin/python3 -c 'import socket; socket.socket(%s).bind((%q, %d))`,
		strings.Join(opts, ", "), addr, port)
}

// IPAddRoute returns a string representing the command to add a route to a
// given IP address and a gateway via the iproute2 utility suite. The function
// takes in a flag called replace which will convert the action to replace the
// route being added if another route exists and matches. This allows for
// idempotency as the "replace" action will not fail if another matching route
// exists, whereas "add" will fail.
func IPAddRoute(ip, gw net.IP, replace bool) string {
	action := "add"
	if replace {
		action = "replace"
	}

	return fmt.Sprintf("ip route %s %s via %s", action, ip.String(), gw.String())
}

// IPDelRoute returns a string representing the command to delete a route to a
// given IP address and a gateway via the iproute2 utility suite.
func IPDelRoute(ip, gw net.IP) string {
	return fmt.Sprintf("ip route del %s via %s", ip.String(), gw.String())
}
