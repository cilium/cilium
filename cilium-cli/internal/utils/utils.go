// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"fmt"
	"os"
	"strconv"

	"github.com/blang/semver/v4"
)

func ParseCiliumVersion(version string) (semver.Version, error) {
	return semver.ParseTolerant(version)
}

const CLIModeVariableName = "CILIUM_CLI_MODE"

// IsInHelmMode returns true if cilium-cli is in "helm" mode. Otherwise, it returns false.
func IsInHelmMode() bool {
	return os.Getenv(CLIModeVariableName) != "classic"
}

func MustParseBool(v string) bool {
	b, err := strconv.ParseBool(v)
	if err != nil {
		panic(fmt.Errorf("failed to parse string [%s] to bool: %s", v, err))
	}
	return b
}
