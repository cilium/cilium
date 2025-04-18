// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package codeowners

import (
	"fmt"
	"os"
	"regexp"

	"github.com/hmarr/codeowners"
)

var ghWorkflowRegexp = regexp.MustCompile("^(?:.+?)/(?:.+?)/(.+?)@.*$")

// Scenario represents a piece of logic in the testsuite with a
// corresponding filepath that indicates ownership (via CODEOWNERS).
// It is used to inform developers who they may consult in the event that a
// test fails without a clear indication why.
type Scenario interface {
	Name() string
	FilePath() string
}

var ErrNoOwners = fmt.Errorf("no owners defined")

type Ruleset struct {
	codeowners.Ruleset

	exclude map[string]struct{}
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

func (r *Ruleset) WithExcludedOwners(excludedOwners []string) *Ruleset {
	excluded := make(map[string]struct{})
	for _, o := range excludedOwners {
		excluded[o] = struct{}{}
	}
	r.exclude = excluded
	return r
}

func (r *Ruleset) WorkflowOwners(includeWorkflowName bool) ([]string, error) {
	var ghWorkflow string
	// Example: cilium/cilium/.github/workflows/conformance-kind-proxy-embedded.yaml@refs/pull/37593/merge
	ghWorkflowRef := os.Getenv("GITHUB_WORKFLOW_REF")
	matches := ghWorkflowRegexp.FindStringSubmatch(ghWorkflowRef)
	// here matches should either be nil (no match) or a slice with two values:
	// the full match and the capture.
	if len(matches) == 2 {
		ghWorkflow = matches[1]
	}

	var owners []string
	if ghWorkflow != "" {
		workflowRule, err := r.Match(ghWorkflow)
		if err == nil && (workflowRule == nil || workflowRule.Owners == nil) {
			err = ErrNoOwners
		}
		if err != nil {
			return nil, fmt.Errorf("matching workflow %s: %w", ghWorkflow, err)
		}

		owners = make([]string, 0, len(workflowRule.Owners))
		for _, o := range workflowRule.Owners {
			owner := o.String()
			if _, ok := r.exclude[owner]; ok {
				continue
			}
			if includeWorkflowName {
				owners = append(owners, fmt.Sprintf("%s (%s)", owner, ghWorkflow))
			} else {
				owners = append(owners, owner)
			}
		}
	}

	return owners, nil
}

func (r *Ruleset) Owners(includeTestCase bool, scenarios ...Scenario) ([]string, error) {
	if r == nil {
		return nil, nil
	}

	rules := make(map[Scenario]*codeowners.Rule)
	for _, scenario := range scenarios {
		rule, err := r.Match(scenario.FilePath())
		if err == nil && (rule == nil || rule.Owners == nil) {
			err = ErrNoOwners
		}
		if err != nil {
			return nil, fmt.Errorf("matching scenario %q (%s): %w", scenario.Name(), scenario.FilePath(), err)
		}
		rules[scenario] = rule
	}

	var owners []string
	for scenario, rule := range rules {
		for _, o := range rule.Owners {
			owner := o.String()
			if _, ok := r.exclude[owner]; ok {
				continue
			}
			if includeTestCase {
				owners = append(owners, fmt.Sprintf("%s (%s)", owner, scenario.Name()))
			} else {
				owners = append(owners, owner)
			}
		}
	}
	return owners, nil
}
