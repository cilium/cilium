// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

const name = "cilium-tooling"

var pythonScript = fmt.Sprintf(`
import importlib.metadata as m
import sys

try:
    dist = m.distribution("%s")
    deps = dist.requires or []
except m.PackageNotFoundError:
    print("ERR_NOT_INSTALLED")
    sys.exit(0)

missing = []
for dep in deps:
    pkg_name = dep.split(";")[0].split(">=")[0].split("==")[0].split("[")[0].strip()
    try:
        m.distribution(pkg_name)
    except m.PackageNotFoundError:
        missing.append(pkg_name)

if missing:
    print("MISSING:" + ",".join(missing))
else:
    print("OK")
`, name)

// A pythonDepsCheck checks that Python dependencies are installed.
type pythonDepsCheck struct{}

func (pythonDepsCheck) Name() string {
	return "python3-deps"
}

func (pythonDepsCheck) Run() (checkResult, string) {
	cmd := exec.Command("python3", "-c", pythonScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return checkWarning, fmt.Sprintf("failed to run Python: %v", err)
	}

	result := strings.TrimSpace(string(output))

	switch {
	case result == "ERR_NOT_INSTALLED":
		return checkWarning, fmt.Sprintf("project '%s' not found", name)

	case strings.HasPrefix(result, "MISSING:"):
		pkgs := strings.TrimPrefix(result, "MISSING:")
		return checkWarning, fmt.Sprintf("the following dependencies are missing: %s", pkgs)

	case result == "OK":
		return checkOK, "found all python3 dependencies"

	default:
		return checkWarning, fmt.Sprintf("unexpected output: %s", result)
	}
}

func (pythonDepsCheck) Hint() string {
	return `Run "pip3 install ." (see pyproject.toml).`
}
