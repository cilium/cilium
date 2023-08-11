// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/hive"
)

func TestCell(t *testing.T) {
	require.NoError(t, hive.New(Cell).Populate())
}
