// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package codeowners

import (
	"fmt"
	"os"

	"github.com/hmarr/codeowners"
)

type Ruleset struct {
	codeowners.Ruleset
}

func Load(paths []string) (*Ruleset, error) {
	var (
		allOwners codeowners.Ruleset
		err       error
	)

	if len(paths) == 0 {
		allOwners, err = codeowners.LoadFileFromStandardLocation()
		if err != nil {
			return nil, fmt.Errorf("while loading: %w", err)
		}
	}

	for _, f := range paths {
		coFile, err := os.Open(f)
		if err != nil {
			return nil, fmt.Errorf("while opening %s: %w", f, err)
		}
		defer coFile.Close()

		owners, err := codeowners.ParseFile(coFile)
		if err != nil {
			return nil, fmt.Errorf("while parsing %s: %w", f, err)
		}

		allOwners = append(allOwners, owners...)
	}

	return &Ruleset{
		Ruleset: allOwners,
	}, nil
}
