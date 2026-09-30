// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// repoWorkflows is the real workflow directory, used to check the classification
// against every workflow in the repository.
const repoWorkflows = "../../" + workflowsDir

func TestWorkflowTriggers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    []string
		wantErr bool
	}{
		{
			name:    "mapping form",
			content: "on:\n  pull_request: {}\n",
			want:    []string{"pull_request"},
		},
		{
			name:    "mapping form with options",
			content: "on:\n  pull_request:\n    branches:\n      - main\n",
			want:    []string{"pull_request"},
		},
		{
			name:    "mapping form with several triggers",
			content: "on:\n  push:\n    branches: [main]\n  pull_request: {}\n",
			want:    []string{"pull_request", "push"},
		},
		{
			name:    "scalar form",
			content: "on: pull_request\n",
			want:    []string{"pull_request"},
		},
		{
			name:    "sequence form",
			content: "on: [push, pull_request]\n",
			want:    []string{"pull_request", "push"},
		},
		{
			name:    "quoted on key",
			content: "\"on\":\n  pull_request: {}\n",
			want:    []string{"pull_request"},
		},
		{
			// pull_request_target contains 'pull_request' as a substring, but
			// GitHub loads those workflows from the base branch.
			name:    "pull_request_target is not pull_request",
			content: "on:\n  pull_request_target:\n    types: [opened]\n",
			want:    []string{"pull_request_target"},
		},
		{
			name:    "workflow_dispatch",
			content: "on:\n  workflow_dispatch:\n    inputs:\n      SHA: {}\n",
			want:    []string{"workflow_dispatch"},
		},
		{
			name:    "schedule only",
			content: "on:\n  schedule:\n    - cron: \"0 0 * * *\"\n",
			want:    []string{"schedule"},
		},
		{
			name:    "missing on key",
			content: "name: no triggers\njobs: {}\n",
			wantErr: true,
		},
		{
			name:    "malformed yaml",
			content: "on: [unterminated\n",
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := workflowTriggers([]byte(tc.content))
			if tc.wantErr {
				require.Error(t, err)
				assert.Nil(t, got)
				return
			}
			require.NoError(t, err)
			names := make([]string, 0, len(got))
			for name := range got {
				names = append(names, name)
			}
			slices.Sort(names)
			assert.Equal(t, tc.want, names)
		})
	}
}

// TestWorkflowTriggersAgainstRepository classifies every workflow in the
// repository. It guards against a workflow using an 'on' form the parser does
// not understand, which would silently flag it as unvalidated.
func TestWorkflowTriggersAgainstRepository(t *testing.T) {
	entries, err := os.ReadDir(repoWorkflows)
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	// A workflow known to be triggered on 'pull_request', and one known not to
	// be, so that the test fails if the classification inverts.
	const (
		testedWorkflow   = "lint-workflows.yaml"
		untestedWorkflow = "auto-labeler.yaml"
	)
	seen := map[string]bool{}

	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !workflowPath.MatchString(".github/workflows/"+name) {
			continue
		}
		content, err := os.ReadFile(filepath.Join(repoWorkflows, name))
		require.NoError(t, err)

		triggers, err := workflowTriggers(content)
		require.NoError(t, err, "%s could not be classified", name)
		seen[name] = triggers[pullRequestTrigger]
	}

	require.Contains(t, seen, testedWorkflow)
	assert.True(t, seen[testedWorkflow], "%s is triggered on pull_request", testedWorkflow)
	require.Contains(t, seen, untestedWorkflow)
	assert.False(t, seen[untestedWorkflow], "%s is a pull_request_target workflow", untestedWorkflow)
}

func TestPullRequestExcludes(t *testing.T) {
	const self = ".github/workflows/w.yaml"
	for _, tc := range []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "no filters at all",
			content: "on:\n  pull_request: {}\n",
		},
		{
			name:    "empty trigger body",
			content: "on:\n  pull_request:\n",
		},
		{
			name:    "scalar form has no filters",
			content: "on: pull_request\n",
		},
		{
			name:    "branches only is not a path filter",
			content: "on:\n  pull_request:\n    branches: [main]\n",
		},
		{
			// The renovate-config-validator.yaml case: the filter cannot match
			// the workflow file, so a change to it runs nothing.
			name:    "paths filter that excludes the workflow itself",
			content: "on:\n  pull_request:\n    paths: ['**renovate.json5']\n",
			want:    true,
		},
		{
			// The tests-cifuzz.yaml workaround: name your own path.
			name:    "paths filter that names the workflow itself",
			content: "on:\n  pull_request:\n    paths:\n      - " + self + "\n      - '**/fuzz_test.go'\n",
		},
		{
			name:    "paths-ignore that does not cover the workflow",
			content: "on:\n  pull_request:\n    paths-ignore: ['Documentation/**', 'test/**']\n",
		},
		{
			name:    "paths-ignore that names the workflow itself",
			content: "on:\n  pull_request:\n    paths-ignore:\n      - " + self + "\n",
			want:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, pullRequestExcludes([]byte(tc.content), self))
		})
	}
}

// TestPullRequestExcludesAgainstRepository pins the behaviour against the three
// real workflows that carry a pull_request path filter.
func TestPullRequestExcludesAgainstRepository(t *testing.T) {
	for name, want := range map[string]bool{
		// paths: ['**renovate.json5'] — a change to the workflow runs nothing.
		"renovate-config-validator.yaml": true,
		// paths: lists its own path.
		"tests-cifuzz.yaml": false,
		// paths-ignore: Documentation and test only.
		"cilium-cli.yaml": false,
		// No filter whatsoever.
		"lint-go.yaml": false,
	} {
		t.Run(name, func(t *testing.T) {
			content, err := os.ReadFile(filepath.Join(repoWorkflows, name))
			require.NoError(t, err)
			assert.Equal(t, want, pullRequestExcludes(content, workflowsDir+"/"+name))
		})
	}
}

func TestWorkflowPath(t *testing.T) {
	for path, want := range map[string]bool{
		".github/workflows/tests-e2e-upgrade.yaml": true,
		".github/workflows/reusable-greetings.yml": true,
		".github/workflows/sub/dir/notes.yaml":     false,
		".github/workflows/notes.txt":              false,
		".github/workflows":                        false,
		".github/actions/e2e/lb.yaml":              false,
		"cilium-cli/connectivity/tests/lrp.go":     false,
	} {
		assert.Equal(t, want, workflowPath.MatchString(path), path)
	}
}

// fetcher serves workflow content for unvalidatedPaths.
func fetcher(contents map[string]string) fetchFunc {
	return func(path string) ([]byte, error) {
		content, ok := contents[path]
		if !ok {
			return nil, fmt.Errorf("404 not found")
		}
		return []byte(content), nil
	}
}

const (
	prWorkflow       = "on:\n  pull_request: {}\njobs: {}\n"
	dispatchWorkflow = "on:\n  workflow_dispatch: {}\njobs: {}\n"
	targetWorkflow   = "on:\n  pull_request_target: {}\njobs: {}\n"
)

// files48192 is the change set of #48192, whose unvalidated .github/ change was
// reverted from main. Its CI files must all be flagged, and the cilium-cli file
// must not be.
var files48192 = []string{
	"cilium-cli/connectivity/tests/lrp.go",
	".github/actions/e2e/lb.yaml",
	".github/actions/lvh-kind/action.yaml",
	".github/workflows/tests-e2e-upgrade.yaml",
}

func TestUnvalidatedPaths(t *testing.T) {
	for _, tc := range []struct {
		name     string
		changed  []string
		contents map[string]string
		want     []finding
	}{
		{
			name:    "no CI changes",
			changed: []string{"cilium-cli/connectivity/tests/lrp.go", "pkg/policy/rules.go"},
			want:    nil,
		},
		{
			name:     "pull_request workflow is validated",
			changed:  []string{".github/workflows/lint-go.yaml"},
			contents: map[string]string{".github/workflows/lint-go.yaml": prWorkflow},
			want:     nil,
		},
		{
			name:     "a dispatchable workflow is flagged and recorded as such",
			changed:  []string{".github/workflows/tests-e2e-upgrade.yaml"},
			contents: map[string]string{".github/workflows/tests-e2e-upgrade.yaml": dispatchWorkflow},
			want:     []finding{{path: ".github/workflows/tests-e2e-upgrade.yaml", dispatchable: true}},
		},
		{
			name:     "a pull_request_target workflow is not dispatchable",
			changed:  []string{".github/workflows/auto-labeler.yaml"},
			contents: map[string]string{".github/workflows/auto-labeler.yaml": targetWorkflow},
			want:     []finding{{path: ".github/workflows/auto-labeler.yaml", dispatchable: false}},
		},
		{
			name:    "composite actions and ariane config need no fetch",
			changed: []string{".github/actions/e2e/lb.yaml", arianeConfigPath},
			want: []finding{
				{path: ".github/actions/e2e/lb.yaml"},
				{path: arianeConfigPath},
			},
		},
		{
			name:     "the #48192 change set",
			changed:  files48192,
			contents: map[string]string{".github/workflows/tests-e2e-upgrade.yaml": dispatchWorkflow},
			want: []finding{
				{path: ".github/actions/e2e/lb.yaml"},
				{path: ".github/actions/lvh-kind/action.yaml"},
				{path: ".github/workflows/tests-e2e-upgrade.yaml", dispatchable: true},
			},
		},
		{
			// Removing a 'pull_request' trigger in the head must re-arm the
			// gate, since the head version is what would run after merge.
			name:     "trigger removed in the head is flagged",
			changed:  []string{".github/workflows/lint-go.yaml"},
			contents: map[string]string{".github/workflows/lint-go.yaml": dispatchWorkflow},
			want:     []finding{{path: ".github/workflows/lint-go.yaml", dispatchable: true}},
		},
		{
			name:     "unfetchable workflow errs towards flagging",
			changed:  []string{".github/workflows/gone.yaml"},
			contents: nil,
			want:     []finding{{path: ".github/workflows/gone.yaml"}},
		},
		{
			name:     "unparseable workflow errs towards flagging",
			changed:  []string{".github/workflows/broken.yaml"},
			contents: map[string]string{".github/workflows/broken.yaml": "on: [unterminated\n"},
			want:     []finding{{path: ".github/workflows/broken.yaml"}},
		},
		{
			name:    "nested file under workflows is not a workflow",
			changed: []string{".github/workflows/sub/dir/notes.yaml"},
			want:    nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := unvalidatedPaths(tc.changed, fetcher(tc.contents), func(string, ...any) {})
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestMarkerRoundTrip(t *testing.T) {
	recorded := []string{
		".github/actions/e2e/lb.yaml",
		// A hostile file name must not be able to close the HTML comment, fake
		// a second marker, or inject a notification.
		".github/actions/x-->`\n@cilium/team <!-- ci-validation-notice v1 -->/action.yaml",
	}
	body := encodeMarker(recorded)
	reported := reportedPaths([]comment{{body: body, isBot: true}}, func(string, ...any) {})
	assert.Len(t, reported, len(recorded))
	for _, path := range recorded {
		assert.Contains(t, reported, path)
	}
}

func TestReportedPaths(t *testing.T) {
	recorded := encodeMarker([]string{".github/actions/e2e/lb.yaml"})

	t.Run("author authored marker is ignored", func(t *testing.T) {
		reported := reportedPaths([]comment{{body: recorded, isBot: false}}, func(string, ...any) {})
		assert.Empty(t, reported)
	})

	t.Run("union across notices", func(t *testing.T) {
		other := encodeMarker([]string{arianeConfigPath})
		reported := reportedPaths([]comment{
			{body: recorded, isBot: true},
			{body: "a plain review comment", isBot: false},
			{body: other, isBot: true},
		}, func(string, ...any) {})
		assert.Len(t, reported, 2)
		assert.Contains(t, reported, ".github/actions/e2e/lb.yaml")
		assert.Contains(t, reported, arianeConfigPath)
	})

	t.Run("unparseable markers are skipped", func(t *testing.T) {
		var logged int
		reported := reportedPaths([]comment{
			{body: "<!-- ci-validation-notice v1 notbase64 -->", isBot: true},
			{body: "<!-- ci-validation-notice v1 " +
				base64.StdEncoding.EncodeToString([]byte("not json")) + " -->", isBot: true},
			{body: recorded, isBot: true},
		}, func(string, ...any) { logged++ })
		assert.Equal(t, 2, logged)
		assert.Len(t, reported, 1)
	})

	t.Run("no marker at all", func(t *testing.T) {
		reported := reportedPaths([]comment{{body: "LGTM", isBot: true}}, func(string, ...any) {})
		assert.Empty(t, reported)
	})
}

func TestFreshFindings(t *testing.T) {
	unvalidated := []finding{
		{path: ".github/actions/e2e/lb.yaml"},
		{path: ".github/actions/lvh-kind/action.yaml"},
		{path: ".github/workflows/tests-e2e-upgrade.yaml", dispatchable: true},
	}
	nolog := func(string, ...any) {}
	recorded := func(f []finding) []comment {
		return []comment{{body: encodeMarker(paths(f)), isBot: true}}
	}

	t.Run("nothing reported yet", func(t *testing.T) {
		assert.Equal(t, unvalidated, freshFindings(unvalidated, nil))
	})

	t.Run("unchanged set is a no-op so clearing the label sticks", func(t *testing.T) {
		reported := reportedPaths(recorded(unvalidated), nolog)
		assert.Empty(t, freshFindings(unvalidated, reported))
	})

	t.Run("a strict subset does not re-arm", func(t *testing.T) {
		reported := reportedPaths(recorded(unvalidated), nolog)
		assert.Empty(t, freshFindings(unvalidated[:1], reported))
	})

	t.Run("a newly added CI file re-arms", func(t *testing.T) {
		reported := reportedPaths(recorded(unvalidated), nolog)
		added := append(slices.Clone(unvalidated), finding{path: arianeConfigPath})
		assert.Equal(t, []finding{{path: arianeConfigPath}}, freshFindings(added, reported))
	})
}

// testPR is the pull request context the rendered commands are built from.
var testPR = prContext{
	number:     48192,
	headSHA:    "75b08d7540be271a1cfd561293ece85f678a379e",
	baseSHA:    "0d2f8e4d67aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	baseBranch: "main",
}

// TestNoticeConverges walks the sequence a pull request goes through: an initial
// notice, a no-op re-run, a re-arm when a CI file is added, and a no-op again.
func TestNoticeConverges(t *testing.T) {
	nolog := func(string, ...any) {}
	workflows := map[string][]byte{
		"tests-e2e-upgrade.yaml": []byte("on:\n  workflow_dispatch: {}\njobs:\n  a:\n" +
			"    steps:\n      - run: work_dir=\".github/actions/e2e\"\n"),
	}
	triggers := map[string][]string{"tests-e2e-upgrade.yaml": {"/ci-e2e-upgrade"}}
	unvalidated := []finding{{path: ".github/actions/e2e/lb.yaml"}}

	// First push: nothing reported, so the notice is posted.
	reported := reportedPaths(nil, nolog)
	fresh := freshFindings(unvalidated, reported)
	require.Equal(t, unvalidated, fresh)
	first := renderNotice(plan(fresh, workflows, triggers, true), paths(unvalidated),
		len(reported) > 0, testPR)
	assert.Contains(t, first, "smallest set")
	assert.NotContains(t, first, "now changes further CI files")

	posted := []comment{{body: first, isBot: true}}

	// Second push, same set: no notice, so a cleared label stays cleared.
	reported = reportedPaths(posted, nolog)
	assert.Empty(t, freshFindings(unvalidated, reported))

	// Third push adds the workflow itself: the gate re-arms, reporting only it.
	added := append(slices.Clone(unvalidated),
		finding{path: ".github/workflows/tests-e2e-upgrade.yaml", dispatchable: true})
	fresh = freshFindings(added, reported)
	require.Len(t, fresh, 1)
	second := renderNotice(plan(fresh, workflows, triggers, true), paths(added),
		len(reported) > 0, testPR)
	assert.Contains(t, second, "now changes further CI files")
	assert.Contains(t, second, "tests-e2e-upgrade.yaml")

	// Fourth push, same set: converged, no third notice.
	posted = append(posted, comment{body: second, isBot: true})
	reported = reportedPaths(posted, nolog)
	assert.Empty(t, freshFindings(added, reported))
}

// codeBlock returns the contents of the fenced block listing the actions.
func codeBlock(t *testing.T, body string) string {
	t.Helper()
	_, rest, ok := strings.Cut(body, "```\n")
	require.True(t, ok)
	block, _, ok := strings.Cut(rest, "\n```")
	require.True(t, ok)
	return block
}

// TestRenderNoticeSpellsOutCommands checks that a reviewer gets a runnable
// command rather than being told to work out which trigger applies.
func TestRenderNoticeSpellsOutCommands(t *testing.T) {
	steps := []step{
		{
			workflow: "tests-e2e-upgrade.yaml",
			triggers: []string{"/ci-e2e-upgrade"},
			method:   methodMirror,
			covers:   []string{".github/workflows/tests-e2e-upgrade.yaml"},
		},
		{
			workflow: "conformance-ipsec-e2e.yaml",
			method:   methodContextRef,
			covers:   []string{".github/actions/e2e/lb.yaml"},
		},
	}
	body := renderNotice(steps, []string{".github/actions/e2e/lb.yaml"}, false, testPR)
	block := codeBlock(t, body)

	// Both workflows are named, numbered, and tagged with their route.
	assert.Contains(t, block, "1. tests-e2e-upgrade.yaml  [M4]")
	assert.Contains(t, block, "2. conformance-ipsec-e2e.yaml  [M3]")

	// The commands are concrete: the real SHAs and the base branch, not
	// placeholders the reviewer has to resolve.
	assert.Contains(t, block, "gh workflow run tests-e2e-upgrade.yaml --ref <branch>")
	assert.Contains(t, block, "gh workflow run conformance-ipsec-e2e.yaml --ref main")
	assert.Contains(t, block, "-f PR-number=48192")
	assert.Contains(t, block, "-f SHA="+testPR.headSHA)
	assert.Contains(t, block, "-f base-SHA="+testPR.baseSHA)
	assert.Contains(t, block, "-f context-ref="+testPR.headSHA)

	// Only the routes in play are explained.
	assert.Equal(t, 1, strings.Count(body, "**"+methodMirror.id+"**"))
	assert.Equal(t, 1, strings.Count(body, "**"+methodContextRef.id+"**"))
	assert.NotContains(t, body, "**"+methodTempTrigger.id+"**")
}

// TestRenderNoticeUsesTriggerWhenDispatchable prefers a one-line comment over a
// command when Ariane can do the dispatch.
func TestRenderNoticeUsesTriggerWhenDispatchable(t *testing.T) {
	steps := []step{{
		workflow: "tests-e2e-upgrade.yaml",
		triggers: []string{"/ci-e2e-upgrade"},
		method:   methodDispatch,
		covers:   []string{".github/actions/e2e/lb.yaml"},
	}}
	block := codeBlock(t, renderNotice(steps, nil, false, testPR))
	assert.Contains(t, block, "comment /ci-e2e-upgrade")
	assert.NotContains(t, block, "gh workflow run")
}

func TestRenderNoticeSanitizesPaths(t *testing.T) {
	nasty := ".github/actions/x`code`\r\n@cilium/team/action.yaml"
	steps := []step{{workflow: "w.yaml", method: methodContextRef, covers: []string{nasty}}}
	body := renderNotice(steps, []string{nasty}, false, testPR)

	block := codeBlock(t, body)
	assert.NotContains(t, block, "`")
	assert.Contains(t, block, ".github/actions/xcode@cilium/team/action.yaml")

	// The raw path is still recorded, so the comparison on the next push is
	// made against what actually changed.
	reported := reportedPaths([]comment{{body: body, isBot: true}}, func(string, ...any) {})
	assert.Contains(t, reported, nasty)
}

func TestRenderNoticeRecordsFullSet(t *testing.T) {
	steps := []step{{method: methodReviewOnly, covers: []string{arianeConfigPath}}}
	all := []string{".github/actions/e2e/lb.yaml", arianeConfigPath}
	body := renderNotice(steps, all, true, testPR)

	match := marker.FindStringSubmatch(body)
	require.NotNil(t, match)
	decoded, err := base64.StdEncoding.DecodeString(match[1])
	require.NoError(t, err)
	var recorded []string
	require.NoError(t, json.Unmarshal(decoded, &recorded))
	assert.Equal(t, all, recorded, "the notice records the full current set, not just the new paths")

	assert.Contains(t, body, validationLabel)
	assert.Contains(t, body, docsURL)
}
