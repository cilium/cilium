// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (js && wasm) || plan9 || windows
// +build js,wasm plan9 windows

package agent

import "syscall"

func setsockoptReuseAddrAndPort(network, address string, c syscall.RawConn) error {
	return nil
}
