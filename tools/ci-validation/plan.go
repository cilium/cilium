// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// The workflows and the Ariane configuration are read from the checkout rather
// than through the API. That checkout is the base branch, so this is trusted
// content: it says which workflows consume a file and which comment dispatches
// them, neither of which the pull request gets to influence.
const (
	workflowsDir      = ".github/workflows"
	arianeConfigFile  = ".github/ariane-config.yaml"
	arianeTriggerName = `^/[A-Za-z0-9][A-Za-z0-9-]*`
)

var arianeTrigger = regexp.MustCompile(arianeTriggerName)

// loadWorkflows reads every workflow definition in dir, keyed by file name.
func loadWorkflows(dir string) (map[string][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	workflows := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !workflowPath.MatchString(workflowsDir+"/"+name) {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", name, err)
		}
		workflows[name] = content
	}
	return workflows, nil
}

// consumersOf returns the workflows that read a path under .github/actions/.
//
// A workflow refers to those files either by directory, as in
// 'uses: ./.github/actions/lvh-kind' for a composite action or
// 'work_dir=".github/actions/e2e"' for a directory of configs, or by the exact
// path. Searching for the path and for each of its ancestors under
// .github/actions/ covers both, and a directory match is not over-reporting:
// the workflows that name a directory merge everything in it.
func consumersOf(target string, workflows map[string][]byte) []string {
	// The exact path, then each ancestor directory. A directory reference has
	// to stop there: a workflow that names one file must not be taken to
	// consume its siblings.
	type candidate struct {
		text  string
		isDir bool
	}
	candidates := []candidate{{target, false}}
	for p := path.Dir(target); strings.HasPrefix(p, actionsPrefix); p = path.Dir(p) {
		candidates = append(candidates, candidate{p, true})
	}

	var consumers []string
	for name, content := range workflows {
		text := string(content)
		if slices.ContainsFunc(candidates, func(c candidate) bool {
			return mentions(text, c.text, c.isDir)
		}) {
			consumers = append(consumers, name)
		}
	}
	sort.Strings(consumers)
	return consumers
}

// mentions reports whether text refers to ref. When ref is a directory, an
// occurrence that continues with '/' is a reference to something inside it, not
// to the directory as a whole, so it does not count.
func mentions(text, ref string, isDir bool) bool {
	for i := 0; i <= len(text)-len(ref); {
		j := strings.Index(text[i:], ref)
		if j < 0 {
			return false
		}
		end := i + j + len(ref)
		if !isDir || end >= len(text) || text[end] != '/' {
			return true
		}
		i = end
	}
	return false
}

// arianeTriggers maps a workflow file name to the comments that dispatch it.
func arianeTriggers(content []byte) (map[string][]string, error) {
	var config struct {
		Triggers map[string]struct {
			Workflows []string `yaml:"workflows"`
		} `yaml:"triggers"`
	}
	if err := yaml.Unmarshal(content, &config); err != nil {
		return nil, fmt.Errorf("parsing the Ariane configuration: %w", err)
	}

	triggers := map[string][]string{}
	for trigger, spec := range config.Triggers {
		// Trigger keys are regular expressions, for example '/test\s*'.
		name := arianeTrigger.FindString(trigger)
		if name == "" {
			continue
		}
		for _, workflow := range spec.Workflows {
			triggers[workflow] = append(triggers[workflow], name)
		}
	}
	for workflow := range triggers {
		sort.Strings(triggers[workflow])
	}
	return triggers, nil
}

// step is one thing a reviewer has to do, and the flagged paths it validates.
type step struct {
	// workflow is the workflow to run, empty when none can be named.
	workflow string
	// heading overrides the display heading when there is no workflow to name.
	heading string
	// triggers are the Ariane comments that dispatch it, if any.
	triggers []string
	method   method
	covers   []string
}

// routeFor picks the validation route for running one workflow. Whether the
// pull request comes from a fork decides more than the trigger does, because
// Ariane dispatches, and checks out, the pull request's own branch only when
// that branch is in this repository.
//
// definitionChanged distinguishes a change to the workflow itself, which needs
// the definition to come from the pull request, from a change to a file the
// workflow merely reads.
func routeFor(definitionChanged, dispatchable, fromFork bool) method {
	switch {
	case !dispatchable:
		// No dispatch to redirect: 'pull_request_target', 'schedule' and
		// 'push' workflows are only ever loaded from the base branch.
		return methodTempTrigger
	case definitionChanged && fromFork:
		return methodMirror
	case definitionChanged:
		return methodDispatch
	case fromFork:
		return methodContextRef
	default:
		return methodDispatch
	}
}

// plan reduces the findings to the smallest set of actions that validates all of
// them.
//
// Running one workflow exercises every flagged file it reads, so the candidates
// are workflows and this is a set cover over the flagged paths. A workflow whose
// own definition changed has to be run, because nothing else exercises that
// definition; the rest are added only while paths remain uncovered. That is what
// keeps a pull request changing both a workflow and a config it consumes down to
// a single action, instead of one per consuming workflow.
func plan(findings []finding, workflows map[string][]byte, triggers map[string][]string, fromFork bool) []step {
	type candidate struct {
		definitionChanged bool
		dispatchable      bool
		covers            []string
	}
	byWorkflow := map[string]*candidate{}
	get := func(name string) *candidate {
		if byWorkflow[name] == nil {
			byWorkflow[name] = &candidate{}
		}
		return byWorkflow[name]
	}

	var reviewOnly, orphans, arianeConfig, pathFiltered []string
	uncovered := map[string]struct{}{}
	for _, f := range findings {
		switch {
		case f.path == arianeConfigPath:
			// Ariane reads its configuration at the same ref it dispatches, so
			// for a pull request from a branch in this repository the proposed
			// configuration is what /test uses. For a fork it reads the target
			// branch instead, and the change cannot be exercised at all.
			if fromFork {
				reviewOnly = append(reviewOnly, f.path)
			} else {
				arianeConfig = append(arianeConfig, f.path)
			}
		case f.prExcluded && !f.dispatchable:
			pathFiltered = append(pathFiltered, f.path)
		case strings.HasPrefix(f.path, actionsPrefix):
			consumers := consumersOf(f.path, workflows)
			if len(consumers) == 0 {
				orphans = append(orphans, f.path)
				continue
			}
			uncovered[f.path] = struct{}{}
			for _, name := range consumers {
				c := get(name)
				c.covers = append(c.covers, f.path)
				if declared, err := workflowTriggers(workflows[name]); err == nil {
					c.dispatchable = declared[dispatchTrigger]
				}
			}
		default:
			uncovered[f.path] = struct{}{}
			c := get(path.Base(f.path))
			c.definitionChanged = true
			c.dispatchable = f.dispatchable
			c.covers = append(c.covers, f.path)
		}
	}

	names := make([]string, 0, len(byWorkflow))
	for name := range byWorkflow {
		names = append(names, name)
	}
	sort.Strings(names)

	// A changed definition can only be exercised by running that workflow.
	var chosen []string
	take := func(name string) {
		chosen = append(chosen, name)
		for _, p := range byWorkflow[name].covers {
			delete(uncovered, p)
		}
	}
	for _, name := range names {
		if byWorkflow[name].definitionChanged {
			take(name)
		}
	}

	// Then cover whatever is left, most-covering workflow first, preferring the
	// earlier name on a tie so that the result is deterministic.
	for len(uncovered) > 0 {
		best, bestCount := "", 0
		for _, name := range names {
			if slices.Contains(chosen, name) {
				continue
			}
			count := 0
			for _, p := range byWorkflow[name].covers {
				if _, ok := uncovered[p]; ok {
					count++
				}
			}
			if count > bestCount {
				best, bestCount = name, count
			}
		}
		if bestCount == 0 {
			break
		}
		take(best)
	}
	sort.Strings(chosen)

	steps := make([]step, 0, len(chosen)+2)
	for _, name := range chosen {
		c := byWorkflow[name]
		steps = append(steps, step{
			workflow: name,
			triggers: triggers[name],
			method:   routeFor(c.definitionChanged, c.dispatchable, fromFork),
			covers:   c.covers,
		})
	}
	if len(orphans) > 0 {
		steps = append(steps, step{
			heading: "(no workflow found that consumes these)",
			method:  routeFor(false, true, fromFork),
			covers:  orphans,
		})
	}
	if len(arianeConfig) > 0 {
		steps = append(steps, step{
			heading:  "(the Ariane configuration)",
			method:   methodDispatch,
			triggers: []string{"/test"},
			covers:   arianeConfig,
		})
	}
	for _, p := range pathFiltered {
		steps = append(steps, step{
			workflow: path.Base(p),
			method:   methodPathFilter,
			covers:   []string{p},
		})
	}
	if len(reviewOnly) > 0 {
		steps = append(steps, step{
			heading: "(cannot be exercised before merge)",
			method:  methodReviewOnly,
			covers:  reviewOnly,
		})
	}
	return steps
}
