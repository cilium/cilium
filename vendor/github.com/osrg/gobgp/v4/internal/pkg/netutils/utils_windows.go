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

//go:build windows

package netutils

import (
	"syscall"
)

func setSockOptInt(sc syscall.RawConn, level, name, value int) error {
	var opterr error
	fn := func(s uintptr) {
		opterr = syscall.SetsockoptInt(syscall.Handle(s), level, name, value)
	}
	err := sc.Control(fn)
	if opterr == nil {
		return err
	}
	return opterr
}

func setSockOptIpTtl(sc syscall.RawConn, family int, value int) error {
	level := syscall.IPPROTO_IP
	name := syscall.IP_TTL
	if family == syscall.AF_INET6 {
		level = syscall.IPPROTO_IPV6
		name = syscall.IPV6_UNICAST_HOPS
	}
	return setSockOptInt(sc, level, name, value)
}
