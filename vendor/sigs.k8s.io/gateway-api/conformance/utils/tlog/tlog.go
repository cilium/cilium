/*
Copyright 2024 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package tlog provides helpers for adding timestamps to test logging.
package tlog

import (
	"fmt"
	"testing"
	"time"
)

var TimeFormat = time.RFC3339Nano

func format(args ...any) string {
	return fmt.Sprintf("%s: %s", time.Now().Format(TimeFormat), fmt.Sprint(args...))
}

func formatf(format string, args ...any) string {
	return fmt.Sprintf("%s: %s", time.Now().Format(TimeFormat), fmt.Sprintf(format, args...))
}

// Log logs to T with a timestamp
func Log(t *testing.T, args ...any) {
	t.Helper()
	t.Log(format(args...))
}

// Logf logs to T with a timestamp
func Logf(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Log(formatf(format, args...))
}

// Error logs to T with a timestamp
func Error(t *testing.T, args ...any) {
	t.Helper()
	t.Error(format(args...))
}

// Errorf logs to T with a timestamp
func Errorf(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Error(formatf(format, args...))
}

// Fatal logs to T with a timestamp
func Fatal(t *testing.T, args ...any) {
	t.Helper()
	t.Fatal(format(args...))
}

// Fatalf logs to T with a timestamp
func Fatalf(t *testing.T, format string, args ...any) {
	t.Helper()
	t.Fatal(formatf(format, args...))
}
