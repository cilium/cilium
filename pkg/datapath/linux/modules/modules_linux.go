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

// tryOpenModulesFile attempts to open and parse a modules.builtin file.
func tryOpenModulesFile(path string) ([]string, error) {
	fModules, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("failed to open builtin modules information at %s: %w", path, err)
	}
	defer fModules.Close()

	return parseBuiltinModulesFile(fModules)
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
		"/lib/modules",
		"/usr/lib/modules",
		"/usr/lib/debug/lib/modules",
	}

	locationSuffix := "modules.builtin"

	release, err := kernelRelease()
	if err != nil {
		return nil, err
	}

	// Iterate over the predefined locations.
	for _, location := range locations {
		fModuleFile := location + fmt.Sprintf("/%s/", release) + locationSuffix
		log.Debugf("trying to detect builtin kernel modules in %s", fModuleFile)

		// Try to open the file at the formatted module path.
		result, err = tryOpenModulesFile(fModuleFile)
		if err == nil {
			log.Debugf("found list of builtin kernel modules in %s", fModuleFile)
			return result, nil
		}

		log.Debugf("list of builtin kernel modules not found in %s, trying to find them in sub-directories of %s", fModuleFile, location)

		// If the file doesn't exist, try to find the correct directory.
		dirEntries, err := os.ReadDir(location)
		if err != nil {
			continue
		}

		// Iterate over all subdirectories in the current location.
		for _, entry := range dirEntries {
			log.Debugf("checking if '%s' is found within '%s'", locationSuffix, entry.Name())
			if entry.IsDir() {
				location = filepath.Join(location, entry.Name(), locationSuffix)
				result, err = tryOpenModulesFile(location)
				if err == nil {
					log.Debugf("found list of builtin kernel modules: %s", location)
					return result, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("no builtin modules found under %+q", fmt.Sprintf("%v", locations))
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
