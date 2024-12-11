// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/blang/semver/v4"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/cilium-cli/defaults"
)

func TestErrorExceptionMatching(t *testing.T) {
	errs := `level=error msg="Cannot forward proxied DNS lookup" DNSRequestID=11649 dnsName=google.com.cluster.local. endpointID=3911 error="failed to dial connection to 10.242.1.245:53: dial udp 10.242.1.208:51871->10.242.1.245:53: bind: address already in use" identity=57932 ipAddr="10.242.1.208:51871" subsys=fqdn/dnsproxy (1 occurrences)
		level=info msg="Cannot forward proxied DNS lookup" DNSRequestID=11649 dnsName=google.com.cluster.local. endpointID=3911 error="failed to dial connection to 10.242.1.245:53: dial udp 10.242.1.208:51871->10.242.1.245:53: bind: address already in use" identity=57932 ipAddr="10.242.1.208:51871" subsys=fqdn/dnsproxy (1 occurrences)
level=info msg="foo"
level=error msg="bar"
level=error error="Failed to update lock:..."
level=warning msg="baz"
level=error msg="bar"
[debug][admin] request complete: path: /server_info
[error][envoy_bug] envoy bug failure: !Thread::MainThread::isMainOrTestThread()
[critical][backtrace] Caught Aborted, suspect faulting address 0xd
`

	for _, tt := range []struct {
		levels        []string
		version       semver.Version
		wantLen       int
		wantLogsCount map[string]int
	}{
		{
			levels:  defaults.LogCheckLevels,
			version: semver.MustParse("1.17.0"),
			wantLen: 4,
			wantLogsCount: map[string]int{
				`level=error msg="bar"`:   2,
				`level=warning msg="baz"`: 1,
				`[error][envoy_bug] envoy bug failure: !Thread::MainThread::isMainOrTestThread()`: 1,
				`[critical][backtrace] Caught Aborted, suspect faulting address 0xd`:              1,
			},
		},
		{
			levels:  defaults.LogCheckLevels,
			version: semver.MustParse("1.16.99"),
			wantLen: 3,
			wantLogsCount: map[string]int{
				`level=error msg="bar"`: 2,
				`[error][envoy_bug] envoy bug failure: !Thread::MainThread::isMainOrTestThread()`: 1,
				`[critical][backtrace] Caught Aborted, suspect faulting address 0xd`:              1,
			},
		},
		{
			levels:  []string{defaults.LogLevelError},
			version: semver.MustParse("1.17.0"),
			wantLen: 3,
			wantLogsCount: map[string]int{
				`level=error msg="bar"`: 2,
				`[error][envoy_bug] envoy bug failure: !Thread::MainThread::isMainOrTestThread()`: 1,
				`[critical][backtrace] Caught Aborted, suspect faulting address 0xd`:              1,
			},
		},
		{
			levels:  []string{},
			version: semver.MustParse("1.17.0"),
			wantLen: 2,
			wantLogsCount: map[string]int{
				`[error][envoy_bug] envoy bug failure: !Thread::MainThread::isMainOrTestThread()`: 1,
				`[critical][backtrace] Caught Aborted, suspect faulting address 0xd`:              1,
			},
		},
	} {
		s := NoErrorsInLogs(tt.version, tt.levels).(*noErrorsInLogs)
		fails := s.findUniqueFailures(errs)
		assert.Len(t, fails, tt.wantLen)
		for wantMsg, wantCount := range tt.wantLogsCount {
			assert.Contains(t, fails, wantMsg)
			assert.Equal(t, wantCount, fails[wantMsg])
		}
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
