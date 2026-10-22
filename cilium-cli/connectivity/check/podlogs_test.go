// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestLogFollowerRead(t *testing.T) {
	at := func(s string) time.Time {
		ts, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatal(err)
		}
		return ts
	}
	long := "level=warn msg=" + strings.Repeat("x", 128*1024)
	stream := "2026-10-21T16:34:53.000000001Z level=warn msg=before\n" +
		"2026-10-21T16:34:54.5Z level=info msg=skipped\n" +
		"2026-10-21T16:34:55Z level=warn msg=kept\n" +
		"2026-10-21T16:34:55Z level=warn msg=same-time\n" +
		"not a timestamp level=warn msg=dropped\n" +
		"2026-10-21T16:34:56Z " + long + "\n" +
		"2026-10-21T16:34:57Z level=warn msg=incomplete"

	f := &logFollower{
		keep:  func(line string) bool { return strings.Contains(line, "level=warn") },
		lines: make(map[string][]LogLine),
	}
	last, err := f.read("id", strings.NewReader(stream), at("2026-10-21T16:34:54Z"))
	assert.ErrorIs(t, err, io.EOF)

	assert.Equal(t, at("2026-10-21T16:34:56Z"), last)
	assert.Equal(t, []LogLine{
		{Time: at("2026-10-21T16:34:55Z"), Text: "level=warn msg=kept"},
		{Time: at("2026-10-21T16:34:55Z"), Text: "level=warn msg=same-time"},
		{Time: at("2026-10-21T16:34:56Z"), Text: long},
	}, f.lines["id"])

	ct := &ConnectivityTest{logFollower: f}
	assert.Equal(t, f.lines["id"], ct.FollowedLogLines("id"))
	assert.Empty(t, ct.FollowedLogLines(""))
	assert.Empty(t, (&ConnectivityTest{}).FollowedLogLines("id"))
}
