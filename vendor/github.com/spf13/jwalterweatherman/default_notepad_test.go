// Copyright © 2016 Steve Francia <spf@spf13.com>.
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package jwalterweatherman

import (
	"bytes"
	"io/ioutil"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestThresholds(t *testing.T) {
	SetStdoutThreshold(LevelError)
	require.Equal(t, StdoutThreshold(), LevelError)
	SetLogThreshold(LevelCritical)
	require.Equal(t, LogThreshold(), LevelCritical)
	require.NotEqual(t, StdoutThreshold(), LevelCritical)
	SetStdoutThreshold(LevelWarn)
	require.Equal(t, StdoutThreshold(), LevelWarn)
}

func TestDefaultLogging(t *testing.T) {
	var outputBuf, logBuf bytes.Buffer

	defaultNotepad.logHandle = &logBuf
	defaultNotepad.outHandle = &outputBuf

	SetLogThreshold(LevelWarn)
	SetStdoutThreshold(LevelError)

	FATAL.Println("fatal err")
	CRITICAL.Println("critical err")
	ERROR.Println("an error")
	WARN.Println("a warning")
	INFO.Println("information")
	DEBUG.Println("debugging info")
	TRACE.Println("trace")

	require.Contains(t, logBuf.String(), "fatal err")
	require.Contains(t, logBuf.String(), "critical err")
	require.Contains(t, logBuf.String(), "an error")
	require.Contains(t, logBuf.String(), "a warning")
	require.NotContains(t, logBuf.String(), "information")
	require.NotContains(t, logBuf.String(), "debugging info")
	require.NotContains(t, logBuf.String(), "trace")

	require.Contains(t, outputBuf.String(), "fatal err")
	require.Contains(t, outputBuf.String(), "critical err")
	require.Contains(t, outputBuf.String(), "an error")
	require.NotContains(t, outputBuf.String(), "a warning")
	require.NotContains(t, outputBuf.String(), "information")
	require.NotContains(t, outputBuf.String(), "debugging info")
	require.NotContains(t, outputBuf.String(), "trace")
}

func TestLogCounter(t *testing.T) {
	defaultNotepad.logHandle = ioutil.Discard
	defaultNotepad.outHandle = ioutil.Discard

	SetLogThreshold(LevelTrace)
	SetStdoutThreshold(LevelTrace)

	FATAL.Println("fatal err")
	CRITICAL.Println("critical err")
	WARN.Println("a warning")
	WARN.Println("another warning")
	INFO.Println("information")
	DEBUG.Println("debugging info")
	TRACE.Println("trace")

	wg := &sync.WaitGroup{}

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				ERROR.Println("error", j)
				// check for data races
				require.True(t, LogCountForLevel(LevelError) > uint64(j))
				require.True(t, LogCountForLevelsGreaterThanorEqualTo(LevelError) > uint64(j))
			}
		}()

	}

	wg.Wait()

	require.Equal(t, uint64(1), LogCountForLevel(LevelFatal))
	require.Equal(t, uint64(1), LogCountForLevel(LevelCritical))
	require.Equal(t, uint64(2), LogCountForLevel(LevelWarn))
	require.Equal(t, uint64(1), LogCountForLevel(LevelInfo))
	require.Equal(t, uint64(1), LogCountForLevel(LevelDebug))
	require.Equal(t, uint64(1), LogCountForLevel(LevelTrace))
	require.Equal(t, uint64(100), LogCountForLevel(LevelError))
	require.Equal(t, uint64(102), LogCountForLevelsGreaterThanorEqualTo(LevelError))
}
