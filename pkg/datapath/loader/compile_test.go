// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/testutils"
)

func TestCompile(t *testing.T) {
	testutils.PrivilegedTest(t)

	debugOutput := func(p *progInfo) *progInfo {
		cpy := *p
		cpy.Output = cpy.Source
		cpy.OutputType = outputSource
		return &cpy
	}

	dirs := getDirs(t)
	for _, prog := range []*progInfo{
		epProg,
		hostEpProg,
		debugOutput(epProg),
		debugOutput(hostEpProg),
	} {
		name := fmt.Sprintf("%s:%s", prog.OutputType, prog.Output)
		t.Run(name, func(t *testing.T) {
			path, err := compile(context.Background(), prog, dirs)
			require.Nil(t, err)

			stat, err := os.Stat(path)
			require.Nil(t, err)
			require.False(t, stat.IsDir())
			require.NotZero(t, stat.Size())
		})
	}
}
