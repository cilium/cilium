// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package modules

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	modulesFilepath = "/proc/modules"
)

func moduleLoader() string {
	return "modprobe"
}

// parseModulesFile returns the list of loaded kernel modules names.
func parseModulesFile(r io.Reader) ([]string, error) {
	var result []string

	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		moduleInfoRaw := scanner.Text()
		moduleInfoSeparated := strings.Split(moduleInfoRaw, " ")
		if len(moduleInfoSeparated) < 6 {
			return nil, fmt.Errorf(
				"invalid module info - it has %d fields (less than 6): %s",
				len(moduleInfoSeparated), moduleInfoRaw)
		}

		result = append(result, moduleInfoSeparated[0])
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

// listModules returns the list of loaded kernel modules names parsed from
// /proc/modules.
func listModules() ([]string, error) {
	fModules, err := os.Open(modulesFilepath)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to open modules information at %s: %s",
			modulesFilepath, err)
	}
	defer fModules.Close()
	return parseModulesFile(fModules)
}
