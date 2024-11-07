// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !darwin && !linux

package script

import (
	"fmt"
	"runtime"
)

func MakeRaw(fd int) (restore func(), err error) {
	return func() {}, fmt.Errorf("MakeRaw: not supported on %s", runtime.GOOS)
}
