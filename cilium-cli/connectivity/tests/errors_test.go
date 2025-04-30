// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/pkg/container/set"
)

func TestErrorExceptionMatching(t *testing.T) {
	errs := `time=2025-04-08T14:27:03Z level=error msg="Cannot forward proxied DNS lookup" DNSRequestID=11649 dnsName=google.com.cluster.local. endpointID=3911 error="failed to dial connection to 10.242.1.245:53: dial udp 10.242.1.208:51871->10.242.1.245:53: bind: address already in use" identity=57932 ipAddr="10.242.1.208:51871" subsys=fqdn/dnsproxy (1 occurrences)
		time=2025-04-08T14:27:04Z level=info msg="Cannot forward proxied DNS lookup" DNSRequestID=11649 dnsName=google.com.cluster.local. endpointID=3911 error="failed to dial connection to 10.242.1.245:53: dial udp 10.242.1.208:51871->10.242.1.245:53: bind: address already in use" identity=57932 ipAddr="10.242.1.208:51871" subsys=fqdn/dnsproxy (1 occurrences)
time="2025-04-08T14:27:03.089560116Z" level=info msg="foo"
time="2025-04-08T14:27:03.095898735Z" level=error msg=bar serviceID=1 source=/go/src/github.com/cilium/cilium/pkg/datapath/linux/node.go:189
time=2025-04-08T14:27:05Z level=error error="Failed to update lock:..."
time=2025-04-08T14:27:07Z level=warning msg="baz"
time=2025-04-08T14:27:09Z level=error msg="bar" serviceID=2 source=/go/src/github.com/cilium/cilium/pkg/datapath/linux/node.go:189
[debug][admin] request complete: path: /server_info
[error][envoy_bug] envoy bug failure: !Thread::MainThread::isMainOrTestThread()
[critical][backtrace] Caught Aborted, suspect faulting address 0xd
`

	for _, tt := range []struct {
		levels         []string
		version        semver.Version
		wantLen        int
		wantLogsCount  map[string]int
		wantExampleLog map[string]set.Set[string]
		wantFilePath   string
	}{
		{
			levels:  defaults.LogCheckLevels,
			version: semver.MustParse("1.17.0"),
			wantLen: 4,
			wantLogsCount: map[string]int{
				`bar`: 2,
				`baz`: 1,
				`[error][envoy_bug] envoy bug failure: !Thread::MainThread::isMainOrTestThread()`: 1,
				`[critical][backtrace] Caught Aborted, suspect faulting address 0xd`:              1,
			},
			wantExampleLog: map[string]set.Set[string]{
				"bar": set.NewSet(
					`time="2025-04-08T14:27:03.095898735Z" level=error msg=bar serviceID=1 source=/go/src/github.com/cilium/cilium/pkg/datapath/linux/node.go:189`,
					`time=2025-04-08T14:27:09Z level=error msg="bar" serviceID=2 source=/go/src/github.com/cilium/cilium/pkg/datapath/linux/node.go:189`,
				),
			},
			wantFilePath: "pkg/datapath/linux/node.go",
		},
		{
			levels:  defaults.LogCheckLevels,
			version: semver.MustParse("1.16.99"),
			wantLen: 3,
			wantLogsCount: map[string]int{
				`bar`: 2,
				`[error][envoy_bug] envoy bug failure: !Thread::MainThread::isMainOrTestThread()`: 1,
				`[critical][backtrace] Caught Aborted, suspect faulting address 0xd`:              1,
			},
			wantFilePath: "pkg/datapath/linux/node.go",
		},
		{
			levels:  []string{defaults.LogLevelError},
			version: semver.MustParse("1.17.0"),
			wantLen: 3,
			wantLogsCount: map[string]int{
				`bar`: 2,
				`[error][envoy_bug] envoy bug failure: !Thread::MainThread::isMainOrTestThread()`: 1,
				`[critical][backtrace] Caught Aborted, suspect faulting address 0xd`:              1,
			},
			wantFilePath: "pkg/datapath/linux/node.go",
		},
		{
			levels:  []string{},
			version: semver.MustParse("1.17.0"),
			wantLen: 2,
			wantLogsCount: map[string]int{
				`[error][envoy_bug] envoy bug failure: !Thread::MainThread::isMainOrTestThread()`: 1,
				`[critical][backtrace] Caught Aborted, suspect faulting address 0xd`:              1,
			},
			// We could probably use additional information with source
			// of logs, for example for envoy logs assign to envoy team,
			// for operator logs, assign to operator team, etc.
			// in case of no source file information.
			wantFilePath: "cilium-cli/connectivity/tests/errors.go",
		},
	} {
		s := NoErrorsInLogs(tt.version, tt.levels, "one.one.one.one", "k8s.io").(*noErrorsInLogs)
		fails, example := s.findUniqueFailures([]byte(errs))
		assert.Len(t, fails, tt.wantLen)
		for wantMsg, wantCount := range tt.wantLogsCount {
			assert.Contains(t, fails, wantMsg)
			assert.Equal(t, wantCount, fails[wantMsg])
			if tt.wantExampleLog != nil {
				if wantExample, ok := tt.wantExampleLog[wantMsg]; ok {
					assert.True(t, wantExample.Has(example[wantMsg]),
						"Expected example log to contain one of %q, but got: %v", wantExample, example[wantMsg])
				}
			}
			assert.Equal(t, tt.wantFilePath, s.FilePath())
		}
	}
}

func TestExtractPathFromLog(t *testing.T) {
	_, thisPath, _, _ := runtime.Caller(0)
	repoDir, _ := filepath.Abs(filepath.Join(thisPath, "..", "..", "..", ".."))
	for _, tt := range []struct {
		testCaseName string
		logLine      string
		wantResult   string
	}{
		{
			testCaseName: "Test extracting path from log for Docker build",
			logLine:      `time=2025-04-08T15:50:26Z level=error source=/go/src/github.com/cilium/cilium/pkg/datapath/linux/node.go:189 msg="Updating tunnel map entry" module=agent.datapath ipAddr=172.18.0.3 allocCIDR=fd00:10:244::/64`,
			wantResult:   "pkg/datapath/linux/node.go",
		},
		{
			testCaseName: "Test extracting path from log for local build",
			logLine:      `time=2025-04-08T15:50:26Z level=error source=` + repoDir + `/pkg/datapath/linux/node.go:189 msg="Updating tunnel map entry"`,
			wantResult:   "pkg/datapath/linux/node.go",
		},
		{
			testCaseName: "Returns empty string if no file is found",
			logLine:      `time=2025-04-08T15:50:26Z level=error msg="Updating tunnel map entry" module=agent.datapath ipAddr=172.18.0.3 allocCIDR=fd00:10:244::/64`,
			wantResult:   "",
		},
	} {
		result := extractPathFromLog(tt.logLine)
		assert.Equal(t, tt.wantResult, result, "Test case %q failed", tt.testCaseName)
	}
}

func TestExtractPackageFromLog(t *testing.T) {
	_, thisPath, _, _ := runtime.Caller(0)
	repoDir, _ := filepath.Abs(filepath.Join(thisPath, "..", "..", "..", ".."))
	for _, tt := range []struct {
		testCaseName string
		logLine      string
		wantResult   string
	}{
		{
			testCaseName: "Test extracting path from log for Docker build",
			logLine:      `time=2025-04-08T15:50:26Z level=error source=/go/src/github.com/cilium/cilium/pkg/datapath/linux/node.go:189 msg="Updating tunnel map entry" module=agent.datapath ipAddr=172.18.0.3 allocCIDR=fd00:10:244::/64`,
			wantResult:   "pkg/datapath/linux",
		},
		{
			testCaseName: "Test extracting path from log for local build",
			logLine:      `time=2025-04-08T15:50:26Z level=error source=` + repoDir + `/pkg/datapath/linux/node.go:189 msg="Updating tunnel map entry"`,
			wantResult:   "pkg/datapath/linux",
		},
		{
			testCaseName: "Returns empty string if no file is found",
			logLine:      `time=2025-04-08T15:50:26Z level=error msg="Updating tunnel map entry" module=agent.datapath ipAddr=172.18.0.3 allocCIDR=fd00:10:244::/64`,
			wantResult:   "",
		},
	} {
		result := extractPackageFromLog(tt.logLine)
		assert.Equal(t, tt.wantResult, result, "Test case %q failed", tt.testCaseName)
	}
}

func TestComputeExpectedDropReasons(t *testing.T) {
	defaultReasons := []string{"reason0", "reason1"}
	tests := []struct {
		inputReasons    []string
		expectedReasons []string
	}{
		// Empty list of reasons.
		{
			inputReasons:    []string{},
			expectedReasons: []string{},
		},
		// Add a reason to default list.
		{
			inputReasons:    []string{"+reason2"},
			expectedReasons: []string{"reason0", "reason1", "reason2"},
		},
		// Remove a reason from default list.
		{
			inputReasons:    []string{"-reason1"},
			expectedReasons: []string{"reason0"},
		},
		// Add a reason then remove it.
		{
			inputReasons:    []string{"+reason2", "-reason2"},
			expectedReasons: []string{"reason0", "reason1"},
		},
		// Remove a reason then add it back.
		{
			inputReasons:    []string{"-reason1", "+reason1"},
			expectedReasons: []string{"reason0", "reason1"},
		},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("InputReasons: %v", test.inputReasons), func(t *testing.T) {
			result := computeExpectedDropReasons(defaultReasons, test.inputReasons)

			// computeExpectedDropReasons doesn't guarantee the order of the
			// emitted string so instead we check the length and that all
			// expected elements are listed.

			for _, expReason := range test.expectedReasons {
				if !strings.Contains(result, fmt.Sprintf("%q", expReason)) {
					t.Errorf("Expected filter to contain %q, but got: %v", expReason, result)
				}
			}

			// We know the expected length because all our test reasons are the same length.
			expectedLength := len(test.expectedReasons) * 9
			if len(test.expectedReasons) > 1 {
				expectedLength += (len(test.expectedReasons) - 1) * 2
			}
			if len(result) != expectedLength {
				t.Errorf("Expected filter of length %d, but got: %v", expectedLength, result)
			}
		})
	}
}
