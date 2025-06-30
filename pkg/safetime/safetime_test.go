// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package safetime

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/logging"
)

type SafetimeSuite struct {
	out    *bytes.Buffer // stores log output
	logger *slog.Logger
}

func (s *SafetimeSuite) SetUpTest(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(
		slog.NewTextHandler(&buf,
			&slog.HandlerOptions{
				ReplaceAttr: logging.ReplaceAttrFnWithoutTimestamp,
			},
		),
	)
	s.logger = logger
	s.out = &buf
}

func TestNegativeDuration(t *testing.T) {
	s := SafetimeSuite{}
	s.SetUpTest(t)

	future := time.Now().Add(time.Second)
	d, ok := TimeSinceSafe(future, s.logger)

	require.False(t, ok)
	require.Equal(t, time.Duration(0), d)
	fmt.Println(s.out.String())
	require.Contains(t, s.out.String(), "BUG: negative duration")
}

func TestNonNegativeDuration(t *testing.T) {
	s := SafetimeSuite{}
	s.SetUpTest(t)

	// To prevent the test case from being flaky on machines with invalid
	// CLOCK_MONOTONIC:
	past := time.Now().Add(-10 * time.Second)
	d, ok := TimeSinceSafe(past, s.logger)

	require.True(t, ok)
	require.Greater(t, int64(d), int64(time.Duration(0)))
	require.Empty(t, s.out.String())
}
