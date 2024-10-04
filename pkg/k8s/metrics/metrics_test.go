// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLastInteraction(t *testing.T) {
	LastInteraction.Reset()
	require.Less(t, time.Since(LastInteraction.Time()), time.Second)
}
