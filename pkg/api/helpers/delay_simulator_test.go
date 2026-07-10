// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type operation int

const (
	operation1 operation = iota
	operation2
)

func TestSetDelay(t *testing.T) {
	d := NewDelaySimulator()
	require.NotNil(t, d)

	d.SetDelay(operation1, time.Second)
	require.Equal(t, time.Second, d.delays[operation1])
	require.Equal(t, time.Duration(0), d.delays[operation2])
}
