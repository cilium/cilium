package check

import (
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, strings.TrimSpace(pingHeaderPattern.ReplaceAllString(tt.args.output, "")) == "")
		})
	}
}
