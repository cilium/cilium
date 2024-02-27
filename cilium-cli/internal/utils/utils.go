// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package utils

import (
	"fmt"
	"strconv"

	"github.com/blang/semver/v4"
)

func ParseCiliumVersion(version string) (semver.Version, error) {
	return semver.ParseTolerant(version)
}

func MustParseBool(v string) bool {
	b, err := strconv.ParseBool(v)
	if err != nil {
		panic(fmt.Errorf("failed to parse string [%s] to bool: %s", v, err))
	}
	return b
}
