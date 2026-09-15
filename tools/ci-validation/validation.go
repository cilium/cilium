// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	// validationLabel blocks merging via maintainers-little-helper, which
	// treats any 'dont-merge/*' label as a merge blocker.
	validationLabel = "dont-merge/needs-ci-validation"

	// pullRequestTrigger is the trigger for which GitHub loads the workflow
	// definition from the pull request itself.
	pullRequestTrigger = "pull_request"

	// dispatchTrigger is the trigger Ariane uses for '/test' and the '/ci-*'
	// comments. It is dispatched against the pull request's own branch when that
	// branch is in this repository, so the proposed definition does run then.
	dispatchTrigger = "workflow_dispatch"

	actionsPrefix    = ".github/actions/"
	arianeConfigPath = arianeConfigFile

	docsURL = "https://docs.cilium.io/en/latest/contributing/testing/ci/#testing-ci-workflow-changes"
)

// workflowPath matches the workflow definitions GitHub actually loads: files
// directly under .github/workflows/ with a .yml or .yaml extension.
var workflowPath = regexp.MustCompile(`^\.github/workflows/[^/]+\.ya?ml$`)

// method is one of the validation routes documented in the CI testing guide.
// The identifiers are the ones that guide's table uses, so that a reviewer can
// look up the full procedure.
type method struct {
	id   string
	help string
}

var (
	methodDispatch = method{"M2",
		"Ariane dispatches this pull request's own branch, so its version is what runs"}
	methodContextRef = method{"M3",
		"the definition stays trusted while `context-ref` supplies the pull request's files"}
	methodMirror = method{"M4",
		"dispatching the mirrored branch is what makes the proposed definition run"}
	methodTempTrigger = method{"M5",
		"there is no dispatch to redirect, so the workflow has to be made to run on a pull request"}
	methodPathFilter = method{"M6",
		"the workflow is triggered on `pull_request` but its paths filter excludes itself, " +
			"so nothing runs for this change"}
	methodReviewOnly = method{"review only",
		"Ariane reads this from the base branch for a fork, so it cannot be exercised beforehand"}
)

// finding is a path whose CI is not exercised by the pull request proposing it.
type finding struct {
	path string
	// dispatchable records whether a changed workflow declares
	// 'workflow_dispatch'. It is false for anything that is not a workflow.
	dispatchable bool
	// prExcluded records a workflow that is triggered on 'pull_request' but
	// whose paths filter excludes the workflow file itself.
	prExcluded bool
}

// workflowTriggers returns the set of triggers a workflow declares, covering the
// mapping (on: {pull_request: ...}), sequence (on: [..., pull_request]) and
// scalar (on: pull_request) forms.
//
// Note that the parser does not apply the YAML 1.1 boolean aliases, so the 'on'
// key is read as the string "on" rather than as 'true'.
func workflowTriggers(content []byte) (map[string]bool, error) {
	var workflow struct {
		On any `yaml:"on"`
	}
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		return nil, fmt.Errorf("parsing workflow: %w", err)
	}

	triggers := map[string]bool{}
	switch on := workflow.On.(type) {
	case string:
		triggers[on] = true
	case []any:
		for _, trigger := range on {
			if name, ok := trigger.(string); ok {
				triggers[name] = true
			}
		}
	case map[string]any:
		for name := range on {
			triggers[name] = true
		}
	case nil:
		return nil, fmt.Errorf("workflow has no 'on' key")
	default:
		return nil, fmt.Errorf("unexpected type %T for the 'on' key", workflow.On)
	}
	return triggers, nil
}

// pullRequestExcludes reports whether a 'paths' or 'paths-ignore' filter on the
// 'pull_request' trigger means that a change to the workflow file itself does not
// fire the event. Such a workflow looks validated because it is triggered on
// 'pull_request', while in fact nothing runs.
//
// The comparison is literal: a 'paths' filter counts as excluding the file unless
// it names it outright, the way tests-cifuzz.yaml lists its own path. That errs
// towards flagging, since GitHub's glob syntax is not reproduced here.
func pullRequestExcludes(content []byte, workflow string) bool {
	var parsed struct {
		On map[string]any `yaml:"on"`
	}
	if err := yaml.Unmarshal(content, &parsed); err != nil {
		return false
	}
	trigger, ok := parsed.On[pullRequestTrigger].(map[string]any)
	if !ok {
		// The scalar and sequence forms of 'on' carry no filters, and
		// 'pull_request:' with no body fires for every change.
		return false
	}
	if paths, ok := trigger["paths"]; ok {
		return !listsPath(paths, workflow)
	}
	if ignored, ok := trigger["paths-ignore"]; ok {
		return listsPath(ignored, workflow)
	}
	return false
}

// listsPath reports whether a YAML sequence names path exactly.
func listsPath(filter any, path string) bool {
	entries, ok := filter.([]any)
	if !ok {
		return false
	}
	for _, entry := range entries {
		if name, ok := entry.(string); ok && name == path {
			return true
		}
	}
	return false
}

// fetchFunc returns the content of a path at the pull request's head.
type fetchFunc func(path string) ([]byte, error)

// unvalidatedPaths returns the changed paths whose CI is not exercised by the
// pull request proposing them.
//
// A workflow is classified from the pull request's OWN (head) version, not from
// the base branch: GitHub evaluates 'pull_request' workflows from the merge ref,
// so a workflow triggered on 'pull_request' in the head is validated by this pull
// request's CI regardless of what the base branch says.
func unvalidatedPaths(changed []string, fetch fetchFunc, logf func(string, ...any)) []finding {
	var unvalidated []finding
	for _, p := range changed {
		switch {
		case p == arianeConfigPath || strings.HasPrefix(p, actionsPrefix):
			unvalidated = append(unvalidated, finding{path: p})
		case workflowPath.MatchString(p):
			content, err := fetch(p)
			var triggers map[string]bool
			var excluded bool
			if err == nil {
				triggers, err = workflowTriggers(content)
				if err == nil && triggers[pullRequestTrigger] {
					excluded = pullRequestExcludes(content, p)
					if !excluded {
						// GitHub loads it from the merge ref, so this
						// pull request runs the proposed version.
						continue
					}
					logf("%s is triggered on pull_request but its paths filter "+
						"excludes itself, so nothing runs for this change", p)
				}
			}
			if err != nil {
				// If the workflow cannot be fetched or parsed, err on the
				// side of flagging it, treating it as not validated.
				logf("Could not classify %s, flagging it: %v", p, err)
			}
			unvalidated = append(unvalidated, finding{
				path:         p,
				dispatchable: triggers[dispatchTrigger],
				prExcluded:   excluded,
			})
		}
	}
	return unvalidated
}

// paths returns just the paths of a set of findings.
func paths(findings []finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.path)
	}
	return out
}

// marker matches the record a notice comment keeps of the paths it reported.
var marker = regexp.MustCompile(`<!-- ci-validation-notice v1 ([A-Za-z0-9+/=]*) -->`)

// encodeMarker records paths in a form that can be recovered from a comment
// body. The paths are base64-encoded because they are pull-request-controlled
// and could otherwise close the HTML comment or break the parse.
func encodeMarker(recorded []string) string {
	encoded, err := json.Marshal(recorded)
	if err != nil {
		// Cannot happen for a []string.
		panic(err)
	}
	return fmt.Sprintf("<!-- ci-validation-notice v1 %s -->",
		base64.StdEncoding.EncodeToString(encoded))
}

// comment is the part of a GitHub comment this tool needs, kept free of API
// types so that the reporting logic can be tested directly.
type comment struct {
	body  string
	isBot bool
}

// reportedPaths returns the union of the paths recorded by every notice already
// posted. Only comments authored by a bot are considered, so that a pull request
// author cannot pre-seed a marker to suppress the notice.
func reportedPaths(comments []comment, logf func(string, ...any)) map[string]struct{} {
	reported := make(map[string]struct{})
	for _, c := range comments {
		if !c.isBot {
			continue
		}
		match := marker.FindStringSubmatch(c.body)
		if match == nil {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(match[1])
		if err != nil {
			logf("Ignoring unparseable notice marker: %v", err)
			continue
		}
		var recorded []string
		if err := json.Unmarshal(decoded, &recorded); err != nil {
			logf("Ignoring unparseable notice marker: %v", err)
			continue
		}
		for _, p := range recorded {
			reported[p] = struct{}{}
		}
	}
	return reported
}

// freshFindings returns the findings no notice has reported yet. Keeping the
// label to those makes clearing it stick: re-running on an unchanged set is a
// no-op, while a newly added CI file re-arms the gate.
func freshFindings(unvalidated []finding, reported map[string]struct{}) []finding {
	var fresh []finding
	for _, f := range unvalidated {
		if _, ok := reported[f.path]; !ok {
			fresh = append(fresh, f)
		}
	}
	return fresh
}

// prContext is what the notice needs in order to spell out runnable commands.
type prContext struct {
	number     int
	headSHA    string
	baseSHA    string
	baseBranch string
}

// sanitize strips the characters with which a pull-request-controlled file name
// could break out of the rendered block.
var sanitize = strings.NewReplacer("`", "", "\r", "", "\n", "")

// dispatchCommand renders the invocation for one workflow against a given ref.
func (c prContext) dispatchCommand(workflow, ref, contextRef string) []string {
	return []string{
		fmt.Sprintf("     gh workflow run %s --ref %s \\", sanitize.Replace(workflow), ref),
		fmt.Sprintf("         -f PR-number=%d -f SHA=%s \\", c.number, c.headSHA),
		fmt.Sprintf("         -f base-SHA=%s -f context-ref=%s", c.baseSHA, contextRef),
	}
}

// instructions renders what a reviewer has to do for one step.
func (s step) instructions(c prContext) []string {
	workflow := sanitize.Replace(s.workflow)
	switch s.method.id {
	case methodDispatch.id:
		if len(s.triggers) > 0 {
			return []string{fmt.Sprintf("     comment %s", strings.Join(s.triggers, " or "))}
		}
		return append([]string{"     dispatch it against this pull request's branch:"},
			c.dispatchCommand(workflow, s.workflow, c.headSHA)...)
	case methodContextRef.id:
		return append([]string{"     dispatch it with the pull request's files as the context:"},
			c.dispatchCommand(workflow, c.baseBranch, c.headSHA)...)
	case methodMirror.id:
		return append([]string{"     mirror this branch to cilium/cilium as <branch>, then:"},
			c.dispatchCommand(workflow, "<branch>", c.headSHA)...)
	case methodTempTrigger.id:
		return []string{
			"     mirror this branch to cilium/cilium under ft/main/, then open a",
			"     test pull request whose BASE is that branch: a pull_request_target",
			fmt.Sprintf("     workflow loads %s from the base, so", workflow),
			"     the proposed definition runs under the real trigger. A schedule",
			"     or push only workflow instead runs by pushing that branch",
		}
	case methodPathFilter.id:
		return []string{
			fmt.Sprintf("     add %s to its own 'paths' filter,", workflow),
			"     the way tests-cifuzz.yaml does, or include a file the filter",
			"     does match in a test pull request so that the workflow runs",
		}
	default:
		return []string{"     review it closely; it cannot be exercised before merge"}
	}
}

// renderNotice builds the comment body. It records the full current set rather
// than only the newly reported paths, so that the most recent notice alone is
// enough to reconstruct it.
func renderNotice(steps []step, unvalidated []string, rearm bool, c prContext) string {
	intro := "This pull request changes CI files that its own CI does not exercise, so " +
		"they are **not automatically validated** before merge. This is the smallest set " +
		"of actions that validates all of them:"
	if rearm {
		intro = "This pull request now changes further CI files that its own CI does not " +
			"exercise, so the `" + validationLabel + "` label has been applied again. " +
			"To validate what was added since the previous notice:"
	}

	// Everything below is rendered inside a fenced block, with backticks and
	// newlines stripped, so that pull-request-controlled file names cannot break
	// out to inject markdown links or notifications.
	var block []string
	for i, s := range steps {
		name := sanitize.Replace(s.workflow)
		if name == "" {
			name = s.heading
		}
		heading := fmt.Sprintf("%2d. %s", i+1, name)
		block = append(block, fmt.Sprintf("%s  [%s]", heading, s.method.id))
		block = append(block, s.instructions(c)...)
		for j, p := range s.covers {
			label := "     covers "
			if j > 0 {
				label = "            "
			}
			block = append(block, label+sanitize.Replace(p))
		}
		if i < len(steps)-1 {
			block = append(block, "")
		}
	}

	// Explain only the routes that actually apply, in the order they appear.
	var legend []string
	seen := map[string]bool{}
	for _, s := range steps {
		if seen[s.method.id] {
			continue
		}
		seen[s.method.id] = true
		legend = append(legend, fmt.Sprintf("- **%s**: %s.", s.method.id, s.method.help))
	}

	return strings.Join([]string{
		encodeMarker(unvalidated),
		intro,
		"",
		"```",
		strings.Join(block, "\n"),
		"```",
		"",
		strings.Join(legend, "\n"),
		"",
		"A reviewer should confirm the changes are safe before running any of this, then " +
			"link the successful runs here.",
		"",
		fmt.Sprintf("See [Testing CI workflow changes](%s) for what each route means. Once "+
			"the changes are validated, a reviewer can remove the `%s` label.",
			docsURL, validationLabel),
	}, "\n")
}
