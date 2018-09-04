// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stackdump

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime/debug"
)

// DebugPanicf is identical to Errorf() except that it will panic if the build
// tag debug is set.
func DebugPanicf(format string, a ...interface{}) {
	debugPanicf(format, a...)
}

// Errorf prints the error message plus a stack trace to os.Stderr
func Errorf(format string, a ...interface{}) {
	stack := debug.Stack()
	printStack(os.Stderr, stack, format, a)
}

// Fprintf prints the error message plus a stack trace to the io.Writer
func Fprintf(w io.Writer, format string, a ...interface{}) {
	stack := debug.Stack()
	printStack(w, stack, format, a)
}

func printStack(writer io.Writer, stack []byte, msg string, a []interface{}) {
	goRoutineNumber := []byte("0")
	newLines := 0

	if bytes.Equal([]byte("goroutine"), stack[:len("goroutine")]) {
		newLines = bytes.Count(stack, []byte{'\n'})
		goroutineLine := bytes.IndexRune(stack, '[')
		goRoutineNumber = stack[:goroutineLine]
	}

	fmt.Fprintf(writer, "%s%s\n", goRoutineNumber, fmt.Sprintf(msg, a...))

	// A stack trace is usually in the following format:
	// goroutine 1432 [running]:
	// runtime/debug.Stack(0xc424c4a370, 0xc421f7f750, 0x1)
	//   /usr/local/go/src/runtime/debug/stack.go:24 +0xa7
	//   ...
	// To know which trace belongs to which go routine we will append the
	// go routine number to every line of the stack trace.
	writer.Write(bytes.Replace(
		stack,
		[]byte{'\n'},
		append([]byte{'\n'}, goRoutineNumber...),
		// Don't replace the last '\n'
		newLines-1),
	)
}
