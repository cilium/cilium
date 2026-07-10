// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAction_PingHeaderPattern(t *testing.T) {
	type args struct {
		output string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Only ping header output",
			args: args{
				output: `PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.`,
			},
			want: true,
		},
		{
			name: "Only ping header output without dot",
			args: args{
				output: `PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data`,
			},
			want: false,
		},
		{
			name: "Splitted ping header output with newline",
			args: args{
				output: `PING 10.0.0.1 (10.0.0.1) 56(84) bytes of 
data.`,
			},
			want: false,
		},
		{
			name: "Ping header output with preceding output",
			args: args{
				output: `First PING 10.0.0.1 (10.0.0.1) 56(84) bytes of 
data.`,
			},
			want: false,
		},
		{
			name: "Full ping command output",
			args: args{
				output: `PING www.google.com(zrh04s15-in-x04.1e100.net (2a00:1450:400a:803::2004)) 56 data bytes
64 bytes from zrh04s15-in-x04.1e100.net (2a00:1450:400a:803::2004): icmp_seq=1 ttl=119 time=5.78 ms
64 bytes from zrh04s15-in-x04.1e100.net (2a00:1450:400a:803::2004): icmp_seq=2 ttl=119 time=6.01 ms

--- www.google.com ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1000ms
rtt min/avg/max/mdev = 5.780/5.895/6.010/0.115 ms`,
			},
			want: false,
		},
		{
			name: "IPv6 ping header only",
			args: args{
				output: `PING 2606:4700:4700::1111(2606:4700:4700::1111) 56 data bytes`,
			},
			want: true,
		},
		{
			name: "IPv6 full ping output",
			args: args{
				output: `PING 2606:4700:4700::1111(2606:4700:4700::1111) 56 data bytes
64 bytes from 2606:4700:4700::1111: icmp_seq=1 ttl=58 time=4.57 ms
64 bytes from 2606:4700:4700::1111: icmp_seq=2 ttl=58 time=5.42 ms

--- 2606:4700:4700::1111 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 4.572/4.994/5.417/0.422 ms`,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, strings.TrimSpace(pingHeaderPattern.ReplaceAllString(tt.args.output, "")) == "")
		})
	}
}

func TestLostCurlExitCode(t *testing.T) {
	// The curl write-out line the connectivity tests use, followed by the
	// response code. On a 503 with --fail --show-error, curl also prints its
	// own error to stderr and exits 22.
	const writeOut = "172.20.0.5:49964 -> 172.20.0.3:30134 = 503\n"
	const curlErr = "curl: (22) The requested URL returned error: 503"

	tests := []struct {
		name     string
		stdout   string
		stderr   string
		wantCode ExitCode
		wantLost bool
	}{
		{
			name:     "curl error on stderr (lost exit status)",
			stdout:   writeOut,
			stderr:   curlErr,
			wantCode: ExitCurlHTTPError,
			wantLost: true,
		},
		{
			name:     "curl error merged into stdout (TTY)",
			stdout:   writeOut + curlErr,
			stderr:   "",
			wantCode: ExitCurlHTTPError,
			wantLost: true,
		},
		{
			name:     "curl timeout error",
			stdout:   "",
			stderr:   "curl: (28) Connection timed out",
			wantCode: ExitCurlTimeout,
			wantLost: true,
		},
		{
			// Genuine success: curl printed a response code but no error
			// marker. This must NOT be treated as a lost exit status, so a
			// real unexpected success is still reported as a failure.
			name:     "successful curl, no error marker",
			stdout:   "172.20.0.5:49964 -> 172.20.0.3:30134 = 200\n",
			stderr:   "",
			wantCode: ExitInvalidCode,
			wantLost: false,
		},
		{
			name:     "empty output",
			stdout:   "",
			stderr:   "",
			wantCode: ExitInvalidCode,
			wantLost: false,
		},
		{
			// A word "curl" without the "(NN)" shape must not match.
			name:     "no parenthesised code",
			stdout:   "curl said hello",
			stderr:   "",
			wantCode: ExitInvalidCode,
			wantLost: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, lost := lostCurlExitCode(*bytes.NewBufferString(tt.stdout), *bytes.NewBufferString(tt.stderr))
			assert.Equal(t, tt.wantLost, lost)
			assert.Equal(t, tt.wantCode, code)
		})
	}
}
