// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netutils

import (
	"net"
	"strings"
	"syscall"
)

func extractFamilyFromAddress(address string) int {
	if ip := net.ParseIP(address); ip != nil && ip.To4() == nil {
		return syscall.AF_INET6
	}
	// default
	return syscall.AF_INET
}

func extractFamilyFromConn(conn net.Conn) int {
	family := syscall.AF_INET
	if strings.Contains(conn.RemoteAddr().String(), "[") {
		family = syscall.AF_INET6
	}
	return family
}

func extractProtoFromAddress(address string) string {
	if ip := net.ParseIP(address); ip != nil && ip.To4() == nil {
		return "tcp6"
	}
	// default to tcp4
	return "tcp4"
}
