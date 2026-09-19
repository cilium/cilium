// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConsumersOf(t *testing.T) {
	workflows := map[string][]byte{
		// Reads a whole directory of configs, as the e2e workflows do.
		"reads-dir.yaml": []byte("jobs:\n  a:\n    steps:\n      - run: |\n          work_dir=\".github/actions/e2e\"\n"),
		// Uses a composite action by directory.
		"uses-action.yaml": []byte("jobs:\n  a:\n    steps:\n      - uses: ./.github/actions/lvh-kind\n"),
		// Names one config file exactly.
		"reads-file.yaml": []byte("jobs:\n  a:\n    steps:\n      - run: cat .github/actions/e2e/ipsec.yaml\n"),
		// Consumes nothing under .github/actions/.
		"unrelated.yaml": []byte("jobs:\n  a:\n    steps:\n      - run: make\n"),
	}

	for _, tc := range []struct {
		name string
		path string
		want []string
	}{
		{
			name: "a config in a directory that is merged wholesale",
			path: ".github/actions/e2e/lb.yaml",
			want: []string{"reads-dir.yaml"},
		},
		{
			name: "a config that is also named exactly",
			path: ".github/actions/e2e/ipsec.yaml",
			want: []string{"reads-dir.yaml", "reads-file.yaml"},
		},
		{
			name: "a composite action referenced by its directory",
			path: ".github/actions/lvh-kind/action.yaml",
			want: []string{"uses-action.yaml"},
		},
		{
			name: "an action nothing consumes",
			path: ".github/actions/orphan/action.yaml",
			want: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, consumersOf(tc.path, workflows))
		})
	}
}

// TestConsumersOfAgainstRepository checks the discovery against the real
// workflows, using the file whose change had to be reverted from main.
func TestConsumersOfAgainstRepository(t *testing.T) {
	workflows, err := loadWorkflows(repoWorkflows)
	require.NoError(t, err)
	require.NotEmpty(t, workflows)

	// Both of these merge every config in the directory with
	// 'cat ${work_dir}/*.yaml', so both really do read lb.yaml.
	consumers := consumersOf(".github/actions/e2e/lb.yaml", workflows)
	assert.Contains(t, consumers, "tests-e2e-upgrade.yaml")
	assert.Contains(t, consumers, "conformance-ipsec-e2e.yaml")

	// A composite action, referenced as 'uses: ./.github/actions/lvh-kind'.
	assert.Contains(t, consumersOf(".github/actions/lvh-kind/action.yaml", workflows),
		"tests-e2e-upgrade.yaml")

	// Nothing consumes a workflow, so this must not match everything.
	assert.NotContains(t, consumersOf(".github/actions/e2e/lb.yaml", workflows),
		"lint-go.yaml")
}

func TestArianeTriggers(t *testing.T) {
	config := []byte(`
triggers:
  /default:
    workflows:
    - tests-smoke-conformance.yaml
  /test\s*:
    workflows:
    - conformance-l7.yaml
    - integration-test.yaml
  /ci-e2e-upgrade:
    workflows:
    - tests-e2e-upgrade.yaml
`)
	triggers, err := arianeTriggers(config)
	require.NoError(t, err)

	// The trigger keys are regular expressions; the name has to be cleaned up.
	assert.Equal(t, []string{"/test"}, triggers["conformance-l7.yaml"])
	assert.Equal(t, []string{"/ci-e2e-upgrade"}, triggers["tests-e2e-upgrade.yaml"])
	assert.Equal(t, []string{"/default"}, triggers["tests-smoke-conformance.yaml"])
	assert.Empty(t, triggers["not-registered.yaml"])
}

// TestArianeTriggersAgainstRepository pins the fact that made #48192 escape:
// tests-e2e-upgrade.yaml is not reached by /test.
func TestArianeTriggersAgainstRepository(t *testing.T) {
	config, err := os.ReadFile("../../" + arianeConfigFile)
	require.NoError(t, err)
	triggers, err := arianeTriggers(config)
	require.NoError(t, err)

	assert.Contains(t, triggers["tests-e2e-upgrade.yaml"], "/ci-e2e-upgrade")
	assert.NotContains(t, triggers["tests-e2e-upgrade.yaml"], "/test")
	assert.Contains(t, triggers["integration-test.yaml"], "/test")
}

func TestRouteFor(t *testing.T) {
	for _, tc := range []struct {
		name                                      string
		definitionChanged, dispatchable, fromFork bool
		want                                      method
	}{
		{
			name:         "only a consumed file changed, from a branch",
			dispatchable: true, want: methodDispatch,
		},
		{
			// The #48192 case: for a fork Ariane points context-ref at the
			// target branch, so it has to be overridden by hand.
			name:         "only a consumed file changed, from a fork",
			dispatchable: true, fromFork: true, want: methodContextRef,
		},
		{
			name:              "the definition changed, from a branch",
			definitionChanged: true, dispatchable: true, want: methodDispatch,
		},
		{
			name:              "the definition changed, from a fork",
			definitionChanged: true, dispatchable: true, fromFork: true, want: methodMirror,
		},
		{
			name:              "not dispatchable, so nothing to redirect",
			definitionChanged: true, want: methodTempTrigger,
		},
		{
			name:     "not dispatchable, consumed file only",
			fromFork: true, want: methodTempTrigger,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want,
				routeFor(tc.definitionChanged, tc.dispatchable, tc.fromFork))
		})
	}
}

func TestPlan(t *testing.T) {
	workflows := map[string][]byte{
		"tests-e2e-upgrade.yaml": []byte("on:\n  workflow_dispatch: {}\njobs:\n  a:\n" +
			"    steps:\n      - run: work_dir=\".github/actions/e2e\"\n" +
			"      - uses: ./.github/actions/lvh-kind\n"),
		"conformance-ipsec-e2e.yaml": []byte("on:\n  workflow_dispatch: {}\njobs:\n  a:\n" +
			"    steps:\n      - run: work_dir=\".github/actions/e2e\"\n"),
		"auto-labeler.yaml": []byte("on:\n  pull_request_target: {}\n"),
	}
	triggers := map[string][]string{
		"tests-e2e-upgrade.yaml":     {"/ci-e2e-upgrade"},
		"conformance-ipsec-e2e.yaml": {"/ci-ipsec-e2e"},
	}

	t.Run("the #48192 change set collapses to a single action", func(t *testing.T) {
		findings := []finding{
			{path: ".github/actions/e2e/lb.yaml"},
			{path: ".github/actions/lvh-kind/action.yaml"},
			{path: ".github/workflows/tests-e2e-upgrade.yaml", dispatchable: true},
		}
		steps := plan(findings, workflows, triggers, true)

		// tests-e2e-upgrade.yaml has to be run because its own definition
		// changed, and that one run also reads lb.yaml and lvh-kind. Dispatching
		// the other consumers would add nothing, so it is not asked for.
		require.Len(t, steps, 1)
		assert.Equal(t, "tests-e2e-upgrade.yaml", steps[0].workflow)
		assert.Equal(t, methodMirror, steps[0].method, "its own definition changed")
		assert.ElementsMatch(t, []string{
			".github/actions/e2e/lb.yaml",
			".github/actions/lvh-kind/action.yaml",
			".github/workflows/tests-e2e-upgrade.yaml",
		}, steps[0].covers)
		assert.Equal(t, []string{"/ci-e2e-upgrade"}, steps[0].triggers)
	})

	t.Run("from a branch the same set is one comment", func(t *testing.T) {
		findings := []finding{
			{path: ".github/actions/e2e/lb.yaml"},
			{path: ".github/workflows/tests-e2e-upgrade.yaml", dispatchable: true},
		}
		steps := plan(findings, workflows, triggers, false)
		require.Len(t, steps, 1)
		assert.Equal(t, methodDispatch, steps[0].method)
		assert.Equal(t, []string{"/ci-e2e-upgrade"}, steps[0].triggers)
	})

	t.Run("a consumed file alone picks one covering workflow, not all", func(t *testing.T) {
		// lvh-kind is read by both workflows; covering it once is enough.
		steps := plan([]finding{{path: ".github/actions/lvh-kind/action.yaml"}},
			workflows, triggers, true)
		require.Len(t, steps, 1)
		assert.Equal(t, "tests-e2e-upgrade.yaml", steps[0].workflow)
		assert.Equal(t, methodContextRef, steps[0].method, "its definition did not change")
	})

	t.Run("two files needing different workflows both get an action", func(t *testing.T) {
		// Only ipsec-e2e reads ipsec.yaml here, so it cannot be covered by the
		// workflow that covers lvh-kind.
		withIpsec := map[string][]byte{
			"tests-e2e-upgrade.yaml": []byte("on:\n  workflow_dispatch: {}\njobs:\n  a:\n" +
				"    steps:\n      - uses: ./.github/actions/lvh-kind\n"),
			"conformance-ipsec-e2e.yaml": []byte("on:\n  workflow_dispatch: {}\njobs:\n  a:\n" +
				"    steps:\n      - run: cat .github/actions/e2e/ipsec.yaml\n"),
		}
		steps := plan([]finding{
			{path: ".github/actions/lvh-kind/action.yaml"},
			{path: ".github/actions/e2e/ipsec.yaml"},
		}, withIpsec, triggers, true)
		require.Len(t, steps, 2)
		assert.Equal(t, "conformance-ipsec-e2e.yaml", steps[0].workflow)
		assert.Equal(t, "tests-e2e-upgrade.yaml", steps[1].workflow)
	})

	t.Run("a pull_request_target workflow needs a temporary trigger", func(t *testing.T) {
		steps := plan([]finding{{path: ".github/workflows/auto-labeler.yaml"}},
			workflows, triggers, false)
		require.Len(t, steps, 1)
		assert.Equal(t, "auto-labeler.yaml", steps[0].workflow)
		assert.Equal(t, methodTempTrigger, steps[0].method)
	})

	// Ariane reads its configuration at the ref it dispatches, so the fork
	// qualifier decides here as it does everywhere else under .github/. PR #48267
	// changed only ariane-config.yaml from a cilium/cilium branch and ci-structure
	// confirmed that /test picked the change up.
	t.Run("ariane config from a branch is validated by /test", func(t *testing.T) {
		steps := plan([]finding{{path: arianeConfigPath}}, workflows, triggers, false)
		require.Len(t, steps, 1)
		assert.Empty(t, steps[0].workflow)
		assert.Equal(t, methodDispatch, steps[0].method)
		assert.Equal(t, []string{"/test"}, steps[0].triggers)
		assert.Equal(t, []string{arianeConfigPath}, steps[0].covers)
	})

	t.Run("ariane config from a fork cannot be exercised", func(t *testing.T) {
		steps := plan([]finding{{path: arianeConfigPath}}, workflows, triggers, true)
		require.Len(t, steps, 1)
		assert.Empty(t, steps[0].workflow)
		assert.Equal(t, methodReviewOnly, steps[0].method)
		assert.Equal(t, []string{arianeConfigPath}, steps[0].covers)
	})

	// A workflow triggered on 'pull_request' whose paths filter excludes itself
	// looks validated but never runs. renovate-config-validator.yaml is the live
	// case: PR #48145 changed it and no renovate.json5, and it did not run.
	t.Run("a self-excluding paths filter gets its own route", func(t *testing.T) {
		steps := plan([]finding{{
			path:       ".github/workflows/renovate-config-validator.yaml",
			prExcluded: true,
		}}, workflows, triggers, false)
		require.Len(t, steps, 1)
		assert.Equal(t, "renovate-config-validator.yaml", steps[0].workflow)
		assert.Equal(t, methodPathFilter, steps[0].method)
	})

	t.Run("a self-excluding filter is moot when it is also dispatchable", func(t *testing.T) {
		steps := plan([]finding{{
			path:         ".github/workflows/tests-e2e-upgrade.yaml",
			dispatchable: true,
			prExcluded:   true,
		}}, workflows, triggers, false)
		require.Len(t, steps, 1)
		assert.Equal(t, methodDispatch, steps[0].method, "the dispatch route still works")
	})

	t.Run("an action with no consumer still gets reported", func(t *testing.T) {
		steps := plan([]finding{{path: ".github/actions/orphan/action.yaml"}},
			workflows, triggers, true)
		require.Len(t, steps, 1)
		assert.Empty(t, steps[0].workflow)
		assert.Equal(t, methodContextRef, steps[0].method)
		assert.Equal(t, []string{".github/actions/orphan/action.yaml"}, steps[0].covers)
	})
}
