// Copyright 2017-2019 Authors of Cilium
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

// +build lockdebug

package lock

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"time"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sasha-s/go-deadlock"
	"github.com/sirupsen/logrus"
)

const (
	// selfishThresholdSec is the number of seconds that should be used when
	// detecting if a lock was held for more than the specified time.
	selfishThresholdSec = 0.1

	// Waiting for a lock for longer than DeadlockTimeout is considered a deadlock.
	// Ignored is DeadlockTimeout <= 0.
	deadLockTimeout = 310 * time.Second
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "lock-lib")

	// selfishThresholdMsg is the message that will be printed when a lock was
	// held for more than selfishThresholdSec.
	selfishThresholdMsg = fmt.Sprintf("Goroutine took lock for more than %.2f seconds", selfishThresholdSec)
)

func init() {
	deadlock.Opts.DeadlockTimeout = deadLockTimeout
}

type internalRWMutex struct {
	deadlock.RWMutex
	t time.Time
}

func (i *internalRWMutex) Lock() {
	i.RWMutex.Lock()
	i.t = time.Now()
}

func (i *internalRWMutex) Unlock() {
	if sec := time.Since(i.t).Seconds(); sec >= selfishThresholdSec {
		printStackTo(sec, debug.Stack(), os.Stderr)
	}
	i.RWMutex.Unlock()
}

func (i *internalRWMutex) UnlockIgnoreTime() {
	i.RWMutex.Unlock()
}

func (i *internalRWMutex) RLock() {
	i.RWMutex.RLock()
}

func (i *internalRWMutex) RUnlock() {
	i.RWMutex.RUnlock()
}

type internalMutex struct {
	deadlock.Mutex
	time.Time
}

func (i *internalMutex) Lock() {
	i.Mutex.Lock()
	i.Time = time.Now()
}

func (i *internalMutex) Unlock() {
	if sec := time.Since(i.Time).Seconds(); sec >= selfishThresholdSec {
		printStackTo(sec, debug.Stack(), os.Stderr)
	}
	i.Mutex.Unlock()
}

func (i *internalMutex) UnlockIgnoreTime() {
	i.Mutex.Unlock()
}

func printStackTo(sec float64, stack []byte, writer io.Writer) {
	goRoutineNumber := []byte("0")
	newLines := 0

	if bytes.Equal([]byte("goroutine"), stack[:len("goroutine")]) {
		newLines = bytes.Count(stack, []byte{'\n'})
		goroutineLine := bytes.IndexRune(stack, '[')
		goRoutineNumber = stack[:goroutineLine]
	}

	log.WithFields(logrus.Fields{
		"seconds":   sec,
		"goroutine": string(goRoutineNumber[len("goroutine") : len(goRoutineNumber)-1]),
	}).Debug(selfishThresholdMsg)

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
