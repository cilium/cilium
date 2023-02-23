// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
)

func main() {
	bin, err := os.Executable()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	debugPort, ok := os.LookupEnv("DEBUG_PORT")
	if !ok || debugPort == "" {
		debugPort = "2345"
	}

	debugContinue := true
	if debugHold, ok := os.LookupEnv("DEBUG_HOLD"); ok && debugHold == "true" {
		debugContinue = false
	}

	args := []string{
		fmt.Sprintf("--listen=:%s", debugPort),
		"--headless=true",
		fmt.Sprintf("--continue=%t", debugContinue),
		"--log=true",
		"--log-output=debugger,debuglineerr,gdbwire,lldbout,rpc",
		"--accept-multiclient",
		"--api-version=2",
		"exec",
		fmt.Sprintf("%s-bin", bin),
		"--",
	}

	args = append(args, os.Args[1:]...)

	cmd := exec.Command("/usr/bin/dlv", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err = cmd.Run(); err != nil {
		if exitErr := (&exec.ExitError{}); errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		} else {
			log.Printf("failed to execute dlv: %v", err)
			os.Exit(1)
		}
	}
}
