// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package internal

import (
	"fmt"
	"path"
	"reflect"
	"runtime"
	"strings"
)

func TrimFuncName(name string) string {
	return strings.TrimPrefix(name, "github.com/cilium/cilium/")
}

func FuncNameAndLocation(fn any) string {
	f := runtime.FuncForPC(reflect.ValueOf(fn).Pointer())
	file, line := f.FileLine(f.Entry())
	name := TrimFuncName(f.Name())
	return fmt.Sprintf("%s (%s:%d)", name, path.Base(file), line)
}
