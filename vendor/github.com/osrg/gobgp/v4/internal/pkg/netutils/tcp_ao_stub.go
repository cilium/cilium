// Copyright (C) 2026 The GoBGP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !linux

package netutils

import (
	"net/netip"
	"syscall"
)

func AddTCPAOKeysSockopt(_ syscall.RawConn, _ netip.Prefix, _ string, _ TCPAOConfig) error {
	return ErrTCPAONotSupported
}

func DeleteTCPAOKeysSockopt(_ syscall.RawConn, _ netip.Prefix, _ string, _ TCPAOConfig) error {
	return ErrTCPAONotSupported
}

func SetTCPAOKeySockopt(_ syscall.RawConn, _ TCPAOConfig, _, _ bool) error {
	return ErrTCPAONotSupported
}

func GetTCPAOKeyStateSockopt(_ syscall.RawConn) ([]TCPAOKeyState, error) {
	return nil, ErrTCPAONotSupported
}

func GetTCPAOSocketCountersSockopt(_ syscall.RawConn) (TCPAOSocketCounters, error) {
	return TCPAOSocketCounters{}, ErrTCPAONotSupported
}
