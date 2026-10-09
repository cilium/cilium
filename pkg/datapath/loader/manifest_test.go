// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/option"
)

// rebuilt reports whether compile replaced the object at path since prev, and returns its current state.
func rebuilt(t *testing.T, path string, prev os.FileInfo) (bool, os.FileInfo) {
	t.Helper()
	fi, err := os.Stat(path)
	require.NoError(t, err)
	return prev == nil || !os.SameFile(prev, fi), fi
}

func TestCompileReusesUnchangedObject(t *testing.T) {
	option.Config.DryMode = true
	t.Cleanup(func() { option.Config.DryMode = false })
	logger := hivetest.Logger(t)
	ctx := t.Context()

	lib, state := t.TempDir(), t.TempDir()
	write := func(path, content string) {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
	}
	write(filepath.Join(lib, "prog.c"), `#include <dep.h>
#include <fallback.h>
#include <unroll.h>
__attribute__((section("tc"), used)) int prog(void)
{
	int sum = 0;
#pragma unroll(UNROLL)
	for (int i = 0; i < 4; i++)
		sum += i;
	return VALUE + FALLBACK + sum;
}
char __license[] __attribute__((section("license"), used)) = "GPL";
`)
	write(filepath.Join(lib, "fallback.h"), "#define FALLBACK 0\n")
	dep := filepath.Join(state, "globals", "dep.h")
	write(dep, "#define VALUE 1\n")
	unroll := filepath.Join(state, "globals", "unroll.h")
	write(unroll, "#define UNROLL 1\n")

	dirs := &directoryInfo{Library: lib, Runtime: state, State: state, Output: state}
	prog := &progInfo{Source: "prog.c", Output: "prog.o", OutputType: outputObject, Reusable: true}
	obj := prog.AbsoluteOutput(dirs)
	var last os.FileInfo
	build := func(recompiles bool) {
		t.Helper()
		path, err := compile(ctx, logger, prog, dirs)
		require.NoError(t, err)
		require.Equal(t, obj, path)
		var got bool
		got, last = rebuilt(t, obj, last)
		require.Equal(t, recompiles, got)
	}

	build(true)
	build(false)

	write(dep, "#define VALUE 2\n")
	build(true)
	build(false)

	// A macro used only in a pragma argument changes the object too.
	write(unroll, "#define UNROLL 4\n")
	build(true)
	build(false)

	// A header appearing earlier in the include path shadows the one clang used.
	shadow := filepath.Join(state, "fallback.h")
	write(shadow, "#define FALLBACK 1\n")
	build(true)
	build(false)
	require.NoError(t, os.Remove(shadow))
	build(true)

	require.NoError(t, os.WriteFile(manifestPath(obj), []byte("{"), 0o600))
	build(true)

	// An agent that does not know about the manifest rewrites the object in place.
	require.NoError(t, os.WriteFile(obj, []byte("foreign"), 0o644))
	build(true)
	build(false)

	require.NoError(t, os.Remove(obj))
	last = nil
	build(true)

	// A codegen flag the preprocessed source does not show recompiles too.
	prog.Options = []string{"-O1"}
	build(true)
	build(false)

	// Programs that do not ask for reuse record nothing.
	write(dep, "#define VALUE 3\n")
	require.NoError(t, os.Remove(manifestPath(obj)))
	prog.Reusable = false
	_, err := compile(ctx, logger, prog, dirs)
	require.NoError(t, err)
	require.NoFileExists(t, manifestPath(obj))
}

func TestCompileReusesBaseProgram(t *testing.T) {
	setupCompilationDirectories(t)
	logger := hivetest.Logger(t)
	ctx := t.Context()
	obj := filepath.Join(option.Config.StateDir, socketObj)

	require.NoError(t, compileDefault(ctx, logger, socketProg, socketObj))
	_, first := rebuilt(t, obj, nil)
	require.NoError(t, compileDefault(ctx, logger, socketProg, socketObj))
	replaced, second := rebuilt(t, obj, first)
	require.False(t, replaced)

	// A compiler environment change leaves the preprocessed source alone but recompiles.
	t.Setenv("CCC_OVERRIDE_OPTIONS", "# +-O1")
	require.NoError(t, compileDefault(ctx, logger, socketProg, socketObj))
	replaced, _ = rebuilt(t, obj, second)
	require.True(t, replaced)
}
