// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package netperf

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/cilium-cli/connectivity/perf/common"
)

type fakeActionError struct{ err error }

type fakeAction struct {
	t           *testing.T
	expectedCmd []string
	output      string
}

func (f *fakeAction) ExecInPod(_ context.Context, cmd []string) {
	if len(f.expectedCmd) > 0 {
		require.Equal(f.t, f.expectedCmd, cmd, "Provided command does not match the expected one")
	}
}

func (f *fakeAction) CmdOutput() string { return f.output }

func (f *fakeAction) Debugf(string, ...any) {}
func (f *fakeAction) Fatalf(format string, args ...any) {
	panic(fakeActionError{fmt.Errorf(format, args...)})
}

func TestNetperfCmd(t *testing.T) {
	const (
		dst      = "1.2.3.4"
		duration = 2 * time.Second
		msgsize  = 1500
		streams  = 3
		outfmt   = "MIN_LATENCY,MEAN_LATENCY,MAX_LATENCY,P50_LATENCY,P90_LATENCY,P99_LATENCY,TRANSACTION_RATE,THROUGHPUT,THROUGHPUT_UNITS"
	)

	tests := []struct {
		name          string
		test          string
		expectedCmd   []string
		output        string
		validate      func(*testing.T, common.PerfResult)
		expectedFatal bool
	}{
		{
			name: "TCP_STREAM",
			test: "TCP_STREAM",
			expectedCmd: []string{"/usr/local/bin/netperf", "-H", dst, "-l", duration.String(), "-t", "TCP_STREAM", "--",
				"-R", "1", "-o", outfmt},
			output: strings.TrimSpace(`
MIGRATED TCP STREAM TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 1.2.3.4 () port 0 AF_INET
Minimum Latency Microseconds,Mean Latency Microseconds,Maximum Latency Microseconds,...
0,14.87,903,15,18,44,1.000,8764.41,10^6bits/s
			`),
			validate: func(t *testing.T, res common.PerfResult) {
				require.NotZero(t, res.Timestamp)
				require.NotNil(t, res.ThroughputMetric)
				require.InDelta(t, 8764.41*1e6, res.ThroughputMetric.Throughput, 1)
				require.Nil(t, res.Latency)
				require.Nil(t, res.TransactionRateMetric)
			},
		},
		{
			name:          "TCP_STREAM (incorrect output 1)",
			test:          "TCP_STREAM",
			output:        strings.TrimSpace(`Unexpected output`),
			expectedFatal: true,
		},
		{
			name:          "TCP_STREAM (incorrect output 2)",
			test:          "TCP_STREAM",
			output:        strings.TrimSpace(`0,14.87,903,15,18,44,1.000,8764.41,bits/s`),
			expectedFatal: true,
		},
		{
			name:          "TCP_STREAM (incorrect output 3)",
			test:          "TCP_STREAM",
			output:        strings.TrimSpace(`0,14.87,903,15,18,44`),
			expectedFatal: true,
		},
		{
			name: "UDP_STREAM",
			test: "UDP_STREAM",
			expectedCmd: []string{"/usr/local/bin/netperf", "-H", dst, "-l", duration.String(), "-t", "UDP_STREAM", "--",
				"-R", "1", "-o", outfmt, "-m", strconv.FormatInt(msgsize, 10)},
			output: strings.TrimSpace(`
MIGRATED UDP STREAM TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 1.2.3.4 () port 0 AF_INET
Minimum Latency Microseconds,Mean Latency Microseconds,Maximum Latency Microseconds,...
8,11.16,455,10,12,23,1.000,1056.18,10^6bits/s
			`),
			validate: func(t *testing.T, res common.PerfResult) {
				require.NotZero(t, res.Timestamp)
				require.NotNil(t, res.ThroughputMetric)
				require.InDelta(t, 1056.18*1e6, res.ThroughputMetric.Throughput, 1)
				require.Nil(t, res.Latency)
				require.Nil(t, res.TransactionRateMetric)
			},
		},
		{
			name: "TCP_STREAM_MULTI",
			test: "TCP_STREAM_MULTI",
			expectedCmd: []string{"/bin/bash", "-c",
				fmt.Sprintf("DIR=$(mktemp -d); for i in {1..%d}; do /usr/local/bin/netperf -H %s -l %s -t TCP_STREAM -- "+
					"-R 1 -o %s > $DIR/out$i.out & done; wait; cat $DIR/*; rm -rf $DIR", streams, dst, duration, outfmt)},
			output: strings.TrimSpace(`
MIGRATED TCP STREAM TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 1.2.3.4 () port 0 AF_INET
Minimum Latency Microseconds,Mean Latency Microseconds,Maximum Latency Microseconds,...
0,14.87,903,15,18,44,1.000,8764.41,10^6bits/s
MIGRATED TCP STREAM TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 1.2.3.4 () port 0 AF_INET
Minimum Latency Microseconds,Mean Latency Microseconds,Maximum Latency Microseconds,...
0,15.00,1366,15,18,41,1.000,8705.54,10^6bits/s
MIGRATED TCP STREAM TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 1.2.3.4 () port 0 AF_INET
Minimum Latency Microseconds,Mean Latency Microseconds,Maximum Latency Microseconds,...
0,13.52,4572,13,20,36,1.000,9649.26,10^6bits/s
			`),
			validate: func(t *testing.T, res common.PerfResult) {
				require.NotZero(t, res.Timestamp)
				require.NotNil(t, res.ThroughputMetric)
				require.InDelta(t, 27119.21*1e6, res.ThroughputMetric.Throughput, 1)
				require.Nil(t, res.Latency)
				require.Nil(t, res.TransactionRateMetric)
			},
		},
		{
			name: "TCP_STREAM_MULTI (incorrect output)",
			test: "TCP_STREAM_MULTI",
			output: strings.TrimSpace(`
0,14.87,903,15,18,44,1.000,8764.41,10^6bits/s
0,15.00,1366,15,18,41,1.000,8705.54,10^6bits/s
			`),
			expectedFatal: true,
		},
		{
			name: "UDP_RR",
			test: "UDP_RR",
			expectedCmd: []string{"/usr/local/bin/netperf", "-H", dst, "-l", duration.String(), "-t", "UDP_RR", "--",
				"-R", "1", "-o", outfmt},
			output: strings.TrimSpace(`
MIGRATED UDP REQUEST/RESPONSE TEST from 0.0.0.0 (0.0.0.0) port 0 AF_INET to 1.2.3.4 () port 0 AF_INET : first burst 0
Minimum Latency Microseconds,Mean Latency Microseconds,Maximum Latency Microseconds,...
15,25.44,4034,19,37,89,39147.099,39147.10,Trans/s
			`),
			validate: func(t *testing.T, res common.PerfResult) {
				require.NotZero(t, res.Timestamp)
				require.Nil(t, res.ThroughputMetric)
				require.NotNil(t, res.Latency)
				require.Equal(t, 15*time.Microsecond, res.Latency.Min)
				require.Equal(t, 25440*time.Nanosecond, res.Latency.Avg)
				require.Equal(t, 4034*time.Microsecond, res.Latency.Max)
				require.Equal(t, 19*time.Microsecond, res.Latency.Perc50)
				require.Equal(t, 37*time.Microsecond, res.Latency.Perc90)
				require.Equal(t, 89*time.Microsecond, res.Latency.Perc99)
				require.NotNil(t, res.TransactionRateMetric)
				require.InDelta(t, 39147.099, res.TransactionRateMetric.TransactionRate, 1e-3)
			},
		},
		{
			name:          "UDP_RR_MULTI (invalid)",
			test:          "UDP_RR_MULTI",
			output:        strings.TrimSpace(`15,25.44,4034,19,37,89,39147.099,39147.10,Trans/s`),
			expectedFatal: true,
		},
		{
			name:          "UDP_RR (incorrect output 1)",
			test:          "UDP_RR",
			output:        strings.TrimSpace(`15,25-44,4034,19,37,89,39147.099,39147.10,Trans/s`),
			expectedFatal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				err, ok := r.(fakeActionError)

				switch {
				case r == nil && tt.expectedFatal:
					require.FailNow(t, "Failf should have been called, but has not")
				case r != nil && ok && !tt.expectedFatal:
					require.FailNow(t, "Failf unexpectedly called", err.err.Error())
				case r != nil && !ok: // We captured an unexpected panic
					panic(r)
				}
			}()

			tt.validate(t, NetperfCmd(context.Background(), dst, common.PerfTests{
				Test:     tt.test,
				Duration: duration,
				MsgSize:  msgsize,
				Streams:  streams,
			}, &fakeAction{t, tt.expectedCmd, tt.output}))
		})
	}

}
