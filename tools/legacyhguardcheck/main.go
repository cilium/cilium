// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"regexp"
	"slices"

	"github.com/cilium/cilium/pkg/safeio"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: legacyhguardcheck <path>")
		os.Exit(1)
	}

	found, err := checkDir(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if found {
		fmt.Fprintln(os.Stderr, "Found legacy header guards, please replace with #pragma once or "+
			"add to the exclude list of a false positive found in 'tools/legacyhguardcheck/main.go'")
		os.Exit(1)
	}
}

func checkDir(dirPath string) (bool, error) {
	var guardFound bool

	dir, err := os.ReadDir(dirPath)
	if err != nil {
		return false, err
	}

	for _, entry := range dir {
		entryName := path.Join(dirPath, entry.Name())
		if entry.IsDir() {
			foundGuard, err := checkDir(entryName)
			if err != nil {
				return false, err
			}
			if foundGuard {
				guardFound = true
			}
			continue
		}

		foundGuard, err := checkFile(entryName)
		if err != nil {
			return false, err
		}
		if foundGuard {
			guardFound = true
		}
	}

	return guardFound, nil
}

var ifndefRegex = regexp.MustCompile(`#ifndef\s+([A-Za-z0-9_]+)\s*\n#define ([A-Za-z0-9_]+)`)

var exclude = []string{
	"bpf/node_config.h",
	"bpf/lib/clustermesh.h",
	"bpf/include/linux/byteorder/big_endian.h",
	"bpf/include/linux/byteorder/little_endian.h",
	"bpf/tests/common.h",
	"bpf/tests/bpf_skb_255_tests.c",
	"bpf/tests/bpf_skb_511_tests.c",
}

func checkFile(filePath string) (bool, error) {
	if slices.Contains(exclude, filePath) {
		return false, nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer f.Close()

	const MB = 1 << 20
	content, err := safeio.ReadAllLimit(f, 128*MB)
	if err != nil {
		return false, err
	}

	for _, match := range ifndefRegex.FindAllSubmatch(content, -1) {
		if bytes.Equal(match[1], match[2]) && bytes.HasPrefix(match[1], []byte("_")) {
			i := bytes.Index(content, match[0])
			line := bytes.Count(content[:i], []byte("\n")) + 1
			fmt.Printf("Found legacy header guard with %s macro at %s:%d\n", match[1], filePath, line)
			return true, nil
		}
	}

	return false, nil
}
