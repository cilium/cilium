// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
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

func Ping6WithID(endpoint string, icmpID uint16) string {
	return fmt.Sprintf("xping -6 -W %d -c %d -x %d %s", PingTimeout, PingCount, icmpID, endpoint)
}

func PingWithID(endpoint string, icmpID uint16) string {
	return fmt.Sprintf("xping -W %d -c %d -x %d %s", PingTimeout, PingCount, icmpID, endpoint)
}

// Wrk runs a standard wrk test for http
func Wrk(endpoint string) string {
	return fmt.Sprintf("wrk -t2 -c100 -d30s -R2000 http://%s", endpoint)
}

// CurlFail returns the string representing the curl command with `-s` and
// `--fail` options enabled to curl the specified endpoint.  It takes a
// variadic optionalValues argument. This is passed on to fmt.Sprintf() and
// used into the curl message. Note that `endpoint` is expected to be a format
// string (first argument to fmt.Sprintf()) if optionalValues are used.
func CurlFail(endpoint string, optionalValues ...interface{}) string {
	statsInfo := `time-> DNS: '%{time_namelookup}(%{remote_ip})', Connect: '%{time_connect}',` +
		`Transfer '%{time_starttransfer}', total '%{time_total}'`

	if len(optionalValues) > 0 {
		endpoint = fmt.Sprintf(endpoint, optionalValues...)
	}
	return fmt.Sprintf(
		`curl -k --path-as-is -s -D /dev/stderr --fail --connect-timeout %d --max-time %d %s -w "%s"`,
		CurlConnectTimeout, CurlMaxTimeout, endpoint, statsInfo)
}

// CurlFailNoStats does the same as CurlFail() except that it does not print
// the stats info. See note about optionalValues on CurlFail().
func CurlFailNoStats(endpoint string, optionalValues ...interface{}) string {
	if len(optionalValues) > 0 {
		endpoint = fmt.Sprintf(endpoint, optionalValues...)
	}
	return fmt.Sprintf(
		`curl -k --path-as-is -s -D /dev/stderr --fail --connect-timeout %[1]d --max-time %[2]d %[3]s`,
		CurlConnectTimeout, CurlMaxTimeout, endpoint)
}

// CurlWithHTTPCode retunrs the string representation of the curl command which
// only outputs the HTTP code returned by its execution against the specified
// endpoint. It takes a variadic optinalValues argument. This is passed on to
// fmt.Sprintf() and uses into the curl message. See note about optionalValues
// on CurlFail().
func CurlWithHTTPCode(endpoint string, optionalValues ...interface{}) string {
	if len(optionalValues) > 0 {
		endpoint = fmt.Sprintf(endpoint, optionalValues...)
	}

	return fmt.Sprintf(
		`curl -k --path-as-is -s  -D /dev/stderr --output /dev/stderr -w '%%{http_code}' --connect-timeout %d %s`,
		CurlConnectTimeout, endpoint)
}

// CurlWithRetries returns the string representation of the curl command that
// retries the request if transient problems occur. The parameter "retries"
// indicates the maximum number of attempts.  If flag "fail" is true, the
// function will call CurlFail() and add --retry flag at the end of the command
// and return.  If flag "fail" is false, the function will generate the command
// with --retry flag and return. See note about optionalValues on CurlFail().
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
		`curl -k --path-as-is -s  -D /dev/stderr --output /dev/stderr --retry %d %s`,
		retries, endpoint)
}

// CurlTimeout does the same as CurlFail() except you can define the timeout.
// See note about optionalValues on CurlFail().
func CurlTimeout(endpoint string, timeout time.Duration, optionalValues ...interface{}) string {
	statsInfo := `time-> DNS: '%{time_namelookup}(%{remote_ip})', Connect: '%{time_connect}',` +
		`Transfer '%{time_starttransfer}', total '%{time_total}'`

	if len(optionalValues) > 0 {
		endpoint = fmt.Sprintf(endpoint, optionalValues...)
	}
	return fmt.Sprintf(
		`curl -k --path-as-is -s -D /dev/stderr --fail --connect-timeout %d --max-time %d %s -w "%s"`,
		timeout, timeout, endpoint, statsInfo)
}

// Netperf returns the string representing the netperf command to use when testing
// connectivity between endpoints.
func Netperf(endpoint string, perfTest PerfTest, options string) string {
	return fmt.Sprintf("netperf -l 3 -t %s -H %s %s", perfTest, endpoint, options)
}

// SuperNetperf returns the string representing the super_netperf command to use when
// testing connectivity between endpoints.
func SuperNetperf(sessions int, endpoint string, perfTest PerfTest, options string) string {
	return fmt.Sprintf("super_netperf %d -t %s -H %s %s", sessions, perfTest, endpoint, options)
}

// Netcat returns the string representing the netcat command to the specified
// endpoint. It takes a variadic optionalValues arguments, This is passed to
// fmt.Sprintf uses in the netcat message. See note about optionalValues on
// CurlFail().
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

// ReadFile returns the string representing a cat command to read the file at
// the give path.
func ReadFile(path string) string {
	return fmt.Sprintf("cat %q", path)
}

// OpenSSLShowCerts retrieve the TLS certificate presented at the given
// host:port when serverName is requested. The openssl cli is available in the
// Cilium pod.
func OpenSSLShowCerts(host string, port uint16, serverName string) string {
	serverNameFlag := ""
	if serverName != "" {
		serverNameFlag = fmt.Sprintf("-servername %q", serverName)
	}
	return fmt.Sprintf("openssl s_client -connect %s:%d %s -showcerts | openssl x509 -outform PEM", host, port, serverNameFlag)
}

// GetBPFPacketsCount returns the number of packets for a given drop reason and
// direction by parsing BPF metrics.
func GetBPFPacketsCount(kubectl *Kubectl, pod, reason, direction string) (int, error) {
	cmd := fmt.Sprintf("cilium-dbg bpf metrics list -o json | jq '[.[] | select(.reason == \"%s\") | select(.direction == \"%s\").packets] | add'", reason, direction)

	res := kubectl.CiliumExecMustSucceed(context.TODO(), pod, cmd)

	return strconv.Atoi(strings.TrimSpace(res.Stdout()))
}
