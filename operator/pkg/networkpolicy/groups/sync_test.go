// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package groups

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestKeysFromGroupLabel(t *testing.T) {

	labels := map[string]string{
		"foo":                              "bar",
		"extgrp.cilium.io/":                "",
		"extgrp.cilium.io/asdf":            "",
		"extgrp.cilium.io/chicken chicken": "",
	}

	expected := []groupKey{
		groupKey("asdf"),
		groupKey("chicken chicken"),
	}

	require.ElementsMatch(t, expected, keysFromGroupLabel(labels))
}
