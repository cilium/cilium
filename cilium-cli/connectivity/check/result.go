// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"fmt"
	"strconv"

	flowpb "github.com/cilium/cilium/api/v1/flow"
)

type Result struct {
	// Request is dropped
	Drop bool

	// Request is dropped at Egress
	EgressDrop bool

	// Request is dropped at Ingress
	IngressDrop bool

	// DropReasonFunc
	DropReasonFunc func(flow *flowpb.Flow) bool

	// No flows are to be expected. Used for ingress when egress drops
	None bool

	// DNSProxy is true when DNS Proxy is to be expected, only valid for egress
	DNSProxy bool

	// L7Proxy is true when L7 proxy (e.g., Envoy) is to be expected
	L7Proxy bool

	// HTTPStatus is non-zero when a HTTP status code in response is to be expected
	HTTP HTTP

	// ExitCode is the expected shell exit code
	ExitCode ExitCode
}

type HTTP struct {
	Status string
	Method string
	URL    string
}

type ExitCode int16

const (
	ExitAnyError    ExitCode = -1
	ExitInvalidCode ExitCode = -2

	ExitCurlHTTPError ExitCode = 22
	ExitCurlTimeout   ExitCode = 28
)

func (e ExitCode) String() string {
	switch e {
	case ExitAnyError:
		return "any"
	case ExitInvalidCode:
		return "invalid"
	default:
		return strconv.Itoa(int(e))
	}
}

func (e ExitCode) Check(code uint8) bool {
	switch e {
	case ExitAnyError:
		return code != 0
	case ExitCode(code):
		return true
	}
	return false
}

func (r Result) String() string {
	if r.None {
		return "None"
	}
	ret := "Allow"
	if r.Drop {
		ret = "Drop"
	}
	if r.DNSProxy {
		ret += "-DNS"
	}
	if r.L7Proxy {
		ret += "-L7"
	}
	if r.HTTP.Status != "" || r.HTTP.Method != "" || r.HTTP.URL != "" {
		ret += "-HTTP"
	}
	if r.HTTP.Method != "" {
		ret += "-"
		ret += r.HTTP.Method
	}
	if r.HTTP.URL != "" {
		ret += "-"
		ret += r.HTTP.URL
	}
	if r.HTTP.Status != "" {
		ret += "-"
		ret += r.HTTP.Status
	}
	if r.ExitCode >= 0 && r.ExitCode <= 255 {
		ret += fmt.Sprintf("-exit(%d)", r.ExitCode)
	}
	return ret
}
