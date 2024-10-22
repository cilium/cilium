// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package modules

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	linux "golang.org/x/sys/unix"
)

const (
	loadedModulesFilepath = "/proc/modules"
)

func moduleLoader() string {
	return "modprobe"
}

// kernelRelease returns the release string of the running kernel.
// Its format depends on the Linux distribution and corresponds to directory
// names in /lib/modules by convention. Some examples are 5.15.17-1-lts and
// 4.19.0-16-amd64.
// Note: copied from /vendor/github.com/cilium/ebpf/internal/version.go
func kernelRelease() (string, error) {
	var uname linux.Utsname
	if err := linux.Uname(&uname); err != nil {
		return "", fmt.Errorf("uname failed: %w", err)
	}

	return linux.ByteSliceToString(uname.Release[:]), nil
}

// parseLoadedModulesFile returns the list of loaded kernel modules names.
func parseLoadedModulesFile(r io.Reader) ([]string, error) {
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

// parseBuiltinModulesFile returns the list of builtin kernel modules names.
func parseBuiltinModulesFile(r io.Reader) ([]string, error) {
	var result []string

	scanner := bufio.NewScanner(r)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		modulePathRaw := scanner.Text()
		moduleFileName := filepath.Base(modulePathRaw)
		moduleFileExt := filepath.Ext(modulePathRaw)
		moduleName := strings.TrimSuffix(moduleFileName, moduleFileExt)
		result = append(result, moduleName)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return result, nil
}

// listLoadedModules returns the parsed list of loaded kernel modules names.
func listLoadedModules() ([]string, error) {
	fModules, err := os.Open(loadedModulesFilepath)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to open loaded modules information at %s: %w",
			loadedModulesFilepath, err)
	}
	defer fModules.Close()
	return parseLoadedModulesFile(fModules)
}

// listBuiltinModules returns the parsed list of builtin kernel modules names.
func listBuiltinModules() ([]string, error) {
	var result []string

	locations := []string{
		"/lib/modules/%s/modules.builtin",
		"/usr/lib/modules/%s/modules.builtin",
		"/usr/lib/debug/lib/modules/%s/modules.builtin",
	}

	release, err := kernelRelease()
	if err != nil {
		return nil, err
	}

	for _, location := range locations {
		fModulePath := fmt.Sprintf(location, release)

		fModules, err := os.Open(fModulePath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}

		if err != nil {
			return nil, fmt.Errorf(
				"failed to open builtin modules information at %s: %w",
				fModulePath, err)
		}

		defer fModules.Close()

		result, err = parseBuiltinModulesFile(fModules)
		if err != nil {
			return nil, err
		}

		break
	}

	return result, nil
}

// listModules returns the list of loaded kernel modules names parsed from
// /proc/modules and from /lib/modules/<version>/modules.builtin.
func listModules() ([]string, error) {
	loadedModules, err := listLoadedModules()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve loaded modules names: %w", err)
	}

	builtinModules, err := listBuiltinModules()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve builtin modules names: %w", err)
	}

	return append(loadedModules, builtinModules...), nil
}
