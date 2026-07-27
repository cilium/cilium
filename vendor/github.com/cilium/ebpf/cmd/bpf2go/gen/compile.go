//go:build !windows

package gen

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type CompileArgs struct {
	// Which compiler to use.
	CC string
	// Command used to strip DWARF from the ELF.
	Strip string
	// Flags to pass to the compiler. This may contain positional arguments as well.
	Flags []string
	// Absolute working directory
	Workdir string
	// Absolute input file name
	Source string
	// Absolute output file name
	Dest string
	// Target to compile for, defaults to compiling generic BPF in host endianness.
	Target           Target
	DisableStripping bool
}

func insertDefaultFlags(flags []string) []string {
	// Default cflags that can be overridden by the user.
	overrideFlags := []string{
		// Code needs to be optimized, otherwise the verifier will often fail
		// to understand it.
		"-O2",
		// Clang defaults to mcpu=probe which checks the kernel that we are
		// compiling on. This isn't appropriate for ahead of time
		// compiled code so force the most compatible version.
		"-mcpu=v1",
	}

	insert := 0

	// Find the first non-positional argument to support CC commands with
	// multiple components. E.g.: BPF2GO_CC="ccache clang" ...
	for ; insert < len(flags); insert++ {
		if strings.HasPrefix(flags[insert], "-") {
			break
		}
	}

	result := append([]string(nil), flags[:insert]...)
	result = append(result, overrideFlags...)
	result = append(result, flags[insert:]...)

	return result
}

// Compile C to a BPF ELF file.
func Compile(args CompileArgs) error {
	cmd := exec.Command(args.CC, insertDefaultFlags(args.Flags)...)
	cmd.Stderr = os.Stderr

	inputDir := filepath.Dir(args.Source)
	relInputDir, err := filepath.Rel(args.Workdir, inputDir)
	if err != nil {
		return err
	}

	target := args.Target
	if target == (Target{}) {
		target.clang = "bpf"
	}

	// C flags that can't be overridden.
	if linux := target.linux; linux != "" {
		cmd.Args = append(cmd.Args, "-D__TARGET_ARCH_"+linux)
	}

	cmd.Args = append(cmd.Args,
		"-Wunused-command-line-argument",
		"-target", target.clang,
		"-c", args.Source,
		"-o", args.Dest,
		// Don't include clang version
		"-fno-ident",
		// Don't output inputDir into debug info
		"-fdebug-prefix-map="+inputDir+"="+relInputDir,
		"-fdebug-compilation-dir", ".",
		// We always want BTF to be generated, so enforce debug symbols
		"-g",
		fmt.Sprintf("-D__BPF_TARGET_MISSING=%q", "GCC error \"The eBPF is using target specific macros, please provide -target that is not bpf, bpfel or bpfeb\""),
	)
	cmd.Dir = args.Workdir

	if err := cmd.Run(); err != nil {
		return err
	}

	if args.DisableStripping {
		return nil
	}

	cmd = exec.Command(args.Strip, "-g", args.Dest)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("strip %s: %w", args.Dest, err)
	}

	return nil
}
