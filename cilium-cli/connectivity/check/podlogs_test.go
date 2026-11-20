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
		"2026-10-21T16:34:56.5Z level=info msg=read-not-kept\n" +
		"2026-10-21T16:34:57Z level=warn msg=incomplete"

	f := &logFollower{
		keep: func(line string) bool { return strings.Contains(line, "level=warn") },
		logs: make(map[string]*followedLog),
	}
	last, err := f.read("id", strings.NewReader(stream), at("2026-10-21T16:34:54Z"))
	assert.ErrorIs(t, err, io.EOF)

	assert.Equal(t, at("2026-10-21T16:34:56.5Z"), last)

	ct := &ConnectivityTest{logFollower: f}
	lines, read := ct.FollowedLog("id")
	assert.Equal(t, []LogLine{
		{Time: at("2026-10-21T16:34:55Z"), Text: "level=warn msg=kept"},
		{Time: at("2026-10-21T16:34:55Z"), Text: "level=warn msg=same-time"},
		{Time: at("2026-10-21T16:34:56Z"), Text: long},
	}, lines)
	assert.Equal(t, last, read)

	for _, ct := range []*ConnectivityTest{ct, {}} {
		lines, read := ct.FollowedLog("other")
		assert.Empty(t, lines)
		assert.True(t, read.IsZero())
	}
}
