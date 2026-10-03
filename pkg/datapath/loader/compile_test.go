// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedCompile(t *testing.T) {
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
			logger := hivetest.Logger(t)
			path, err := compile(context.Background(), logger, prog, dirs)
			require.NoError(t, err)

			stat, err := os.Stat(path)
			require.NoError(t, err)
			require.False(t, stat.IsDir())
			require.NotZero(t, stat.Size())
		})
	}
}

func TestCompileKeepsObjectOnFailure(t *testing.T) {
	option.Config.DryMode = true
	t.Cleanup(func() { option.Config.DryMode = false })
	logger := hivetest.Logger(t)

	lib, state := t.TempDir(), t.TempDir()
	src := filepath.Join(lib, "prog.c")
	require.NoError(t, os.WriteFile(src, []byte(`__attribute__((section("tc"), used)) int prog(void) { return 0; }
char __license[] __attribute__((section("license"), used)) = "GPL";
`), 0o644))
	dirs := &directoryInfo{Library: lib, Runtime: state, State: state, Output: state}
	prog := &progInfo{Source: "prog.c", Output: "prog.o", OutputType: outputObject}

	obj, err := compile(t.Context(), logger, prog, dirs)
	require.NoError(t, err)
	want, err := os.ReadFile(obj)
	require.NoError(t, err)

	// A failed compile keeps the previous object and leaves no temporary file.
	require.NoError(t, os.WriteFile(src, []byte("int prog(void) { return ( }\n"), 0o644))
	_, err = compile(t.Context(), logger, prog, dirs)
	require.Error(t, err)
	got, err := os.ReadFile(obj)
	require.NoError(t, err)
	require.True(t, bytes.Equal(want, got), "the failed compile replaced the object")
	require.NoFileExists(t, obj+".tmp")
}
