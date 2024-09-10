// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"fmt"
	"os"
	"slices"

	"github.com/google/go-licenses/licenses"
)

var includeTests bool

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <package1> [<package2> ...]", os.Args[0])
		os.Exit(1)
	}

	fmt.Println("Starting licenses check for third party Go dependencies...")
	unauthorized, err := check(os.Args[1:]...)
	if err != nil {
		fmt.Printf("Failed to check licenses: %v\n", err)
		os.Exit(1)
	}
	if len(unauthorized) > 0 {
		fmt.Println("\nThe third party dependencies below are not allowed under the CNCF's IP policy:")
		for _, f := range unauthorized {
			fmt.Printf("  - %s\n", f)
		}
		fmt.Println("\nProjects under the following licenses are generally accepted:")
		for _, l := range allowedLicenses {
			fmt.Printf("  - %s\n", l)
		}
		fmt.Println("\nUnder certain circumstances, exceptions can be made for projects using a different license. For more information, please consult the following resources:\nhttps://github.com/cncf/foundation/blob/main/allowed-third-party-license-policy.md\nhttps://github.com/cncf/foundation/tree/main/license-exceptions")
		os.Exit(1)
	}
	fmt.Println("Licenses check OK")
}

func check(path ...string) ([]string, error) {
	var unauthorized []string

	classifier, err := licenses.NewClassifier()
	if err != nil {
		return nil, err
	}
	libs, err := licenses.Libraries(context.Background(), classifier, includeTests, pkgExceptions, path...)
	if err != nil {
		return nil, err
	}

	for _, lib := range libs {
		if lib.LicenseFile == "" {
			unauthorized = append(unauthorized, fmt.Sprintf("%s (NO LICENSE FOUND)", lib.Name()))
			continue
		}
		for _, license := range lib.Licenses {
			if !slices.Contains(allowedLicenses, license.Name) {
				unauthorized = append(unauthorized, fmt.Sprintf("%s (%s)", lib.Name(), license.Name))
			}
		}
	}
	return unauthorized, nil
}
