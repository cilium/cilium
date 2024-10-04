// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package safetime

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type SafetimeSuite struct {
	out    *bytes.Buffer // stores log output
	logger *logrus.Entry
}

func (s *SafetimeSuite) SetUpTest(t *testing.T) {
	s.out = &bytes.Buffer{}
	logger := logrus.New()
	logger.Out = s.out
	s.logger = logrus.NewEntry(logger)
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
