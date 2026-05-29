// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
)

// C2GoArray transforms an hexadecimal string representation into a byte slice.
// Example:
// str := "0x12, 0xff, 0x0, 0x1"
// fmt.Print(C2GoArray(str)) //`{0x12, 0xFF, 0x0, 0x01}`"
func C2GoArray(str string) []byte {
	ret := []byte{}

	if str == "" {
		return ret
	}

	for hexDigit := range strings.SplitSeq(str, ", ") {
		strDigit := strings.TrimPrefix(hexDigit, "0x")
		digitUint64, err := strconv.ParseUint(strDigit, 16, 8)
		if err != nil {
			return nil
		}
		ret = append(ret, byte(digitUint64))
	}
	return ret
}

// GoArray2C transforms a byte slice into its hexadecimal string representation.
// Example:
// array := []byte{0x12, 0xFF, 0x0, 0x01}
// fmt.Print(GoArray2C(array)) // "{ 0x12, 0xff, 0x0, 0x1 }"
func GoArray2C(array []byte) string {
	return goArray2C(array, true)
}

// GoArray2CNoSpaces does the same as GoArray2C, but no spaces are used in
// the final output.
// Example:
// array := []byte{0x12, 0xFF, 0x0, 0x01}
// fmt.Print(GoArray2CNoSpaces(array)) // "{0x12,0xff,0x0,0x1}"
func GoArray2CNoSpaces(array []byte) string {
	return goArray2C(array, false)
}

func goArray2C(array []byte, space bool) string {
	ret := ""
	format := ",%#x"
	if space {
		format = ", %#x"
	}

	for i, e := range array {
		if i == 0 {
			ret = ret + fmt.Sprintf("%#x", e)
		} else {
			ret = ret + fmt.Sprintf(format, e)
		}
	}
	return ret
}

// RequireRootPrivilege checks if the user running cmd is root. If not, it exits the program
func RequireRootPrivilege(cmd string) {
	if os.Getuid() != 0 {
		fmt.Fprintf(os.Stderr, "Please run %q command(s) with root privileges.\n", cmd)
		os.Exit(1)
	}
}

// MergeChannels forwards the first value received on any of the input channels.
// The goroutine it starts is bound to ctx, so it is reclaimed on cancellation
// even if no input ever fires and the caller abandons the returned channel.
func MergeChannels[T any](ctx context.Context, chans ...<-chan T) <-chan T {
	out := make(chan T)
	cases := make([]reflect.SelectCase, 0, len(chans)+1)
	for _, ch := range chans {
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(ch),
		})
	}
	ctxCase := len(cases)
	cases = append(cases, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(ctx.Done()),
	})
	go func() {
		defer close(out)
		chosen, value, ok := reflect.Select(cases)
		if chosen == ctxCase || !ok {
			return
		}
		select {
		case out <- value.Interface().(T):
		case <-ctx.Done():
		}
	}()
	return out
}
