// Copyright 2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package loader

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// ProgInfo describes a program to be compiled with the expected output format
type ProgInfo struct {
	// Source is the program source to be compiled
	Source string
	// Output is the expected filename produced from the source
	Output string
	// OutputType of the product (obj, asm)
	OutputType string
}

// InfoDirectories includes relevant directories for compilation and linking
type InfoDirectories struct {
	// Library contains the library code to be used for compilation
	Library string
	// Runtime contains headers for compilation
	Runtime string
	// Output is the directory where the files will be stored
	Output string
}

// Compile the program
func Compile(prog ProgInfo, dir InfoDirectories) error {
	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()

	// Compilation is split between two exec calls. First clang generates
	// LLVM bitcode and then later llc compiles it to assembly.

	clangOutput := fmt.Sprintf("%s/%s.bc", dir.Output, prog.Source)
	out, err := exec.CommandContext(ctx, "clang", "-O2", "-target", "bpf", "-emit-llvm",
		"-Wno-address-of-packed-member", "-Wno-unknown-warning-option",
		fmt.Sprintf("-I%s/globals", dir.Runtime),
		fmt.Sprintf("-I%s", dir.Output),
		fmt.Sprintf("-I%s/include", dir.Library),
		fmt.Sprintf("-D__NR_CPUS__=%d", runtime.NumCPU()),
		"-c", fmt.Sprintf("%s/%s", dir.Library, prog.Source),
		"-o", clangOutput).CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		log.Errorf("Command execution failed: Timeout for %s %s", prog, out)
		return ctx.Err()
	}
	if err != nil {
		log.WithError(err)
		return fmt.Errorf("Error: %q command output: %q", err, out)
	}
	defer os.Remove(clangOutput)

	out, err = exec.CommandContext(ctx, "llc", "-march=bpf", "-mcpu=probe",
		fmt.Sprintf("-filetype=%s", prog.OutputType), clangOutput,
		"-o", fmt.Sprintf("%s/%s", dir.Output, prog.Output),
	).CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		log.Errorf("Command execution failed: Timeout for %s %s", clangOutput, out)
		return ctx.Err()
	}
	if err != nil {
		log.WithError(err)
		return fmt.Errorf("error: %q command output: %q", err, out)
	}

	return nil
}

// Preprocess execute Clang's preprocessor stage
func Preprocess(prog ProgInfo, dir InfoDirectories) error {
	ctx, cancel := context.WithTimeout(context.Background(), ExecTimeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "clang", "-E", "-O2", "-target", "bpf",
		fmt.Sprintf("-I%s/globals", dir.Runtime),
		fmt.Sprintf("-I%s", dir.Output),
		fmt.Sprintf("-I%s/include", dir.Library),
		"-c", fmt.Sprintf("%s/%s", dir.Library, prog.Source),
		"-o", fmt.Sprintf("%s/%s", dir.Output, prog.Output)).CombinedOutput()

	if ctx.Err() == context.DeadlineExceeded {
		log.Errorf("Command execution failed: Timeout for %s %s", prog, out)
		return ctx.Err()
	}
	if err != nil {
		log.WithError(err)
		return fmt.Errorf("Error: %q command output: %q", err, out)
	}

	return nil
}
