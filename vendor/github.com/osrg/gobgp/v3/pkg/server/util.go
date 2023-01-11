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
//go:build !windows
// +build !windows

package server

import (
	"net"
	"strings"
	"syscall"

	"github.com/eapache/channels"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

func cleanInfiniteChannel(ch *channels.InfiniteChannel) {
	ch.Close()
	// drain all remaining items
	for range ch.Out() {
	}
}

// Returns the binary formatted Administrative Shutdown Communication from the
// given string value.
func newAdministrativeCommunication(communication string) (data []byte) {
	if communication == "" {
		return nil
	}
	com := []byte(communication)
	if len(com) > bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX {
		data = []byte{bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX}
		data = append(data, com[:bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX]...)
	} else {
		data = []byte{byte(len(com))}
		data = append(data, com...)
	}
	return data
}

// Parses the given NOTIFICATION message data as a binary value and returns
// the Administrative Shutdown Communication in string and the rest binary.
func decodeAdministrativeCommunication(data []byte) (string, []byte) {
	if len(data) == 0 {
		return "", data
	}
	communicationLen := int(data[0])
	if communicationLen > bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX {
		communicationLen = bgp.BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX
	}
	if communicationLen > len(data)-1 {
		communicationLen = len(data) - 1
	}
	return string(data[1 : communicationLen+1]), data[communicationLen+1:]
}

func extractFamilyFromTCPConn(conn *net.TCPConn) int {
	family := syscall.AF_INET
	if strings.Contains(conn.RemoteAddr().String(), "[") {
		family = syscall.AF_INET6
	}
	return family
}

func setsockOptString(sc syscall.RawConn, level int, opt int, str string) error {
	var opterr error
	fn := func(s uintptr) {
		opterr = syscall.SetsockoptString(int(s), level, opt, str)
	}
	err := sc.Control(fn)
	if opterr == nil {
		return err
	}
	return opterr
}

func setsockOptInt(sc syscall.RawConn, level, name, value int) error {
	var opterr error
	fn := func(s uintptr) {
		opterr = syscall.SetsockoptInt(int(s), level, name, value)
	}
	err := sc.Control(fn)
	if opterr == nil {
		return err
	}
	return opterr
}

func setsockoptIpTtl(sc syscall.RawConn, family int, value int) error {
	level := syscall.IPPROTO_IP
	name := syscall.IP_TTL
	if family == syscall.AF_INET6 {
		level = syscall.IPPROTO_IPV6
		name = syscall.IPV6_UNICAST_HOPS
	}
	return setsockOptInt(sc, level, name, value)
}
