// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linters

import (
	"fmt"

	"k8s.io/apimachinery/pkg/util/sets"
)

// PreFlightLinter ensures that enabling preflight produces an
// entirely distinct set of objects.
//
// This is because we expect to be able to install cilium in pre-flight
// mode on top of an existing cilium installation during upgrades.
type PreFlightLinter struct{}

var _ Linter = (*PreFlightLinter)(nil)

func (*PreFlightLinter) Name() string {
	return "PreFlightLinter"
}

func (*PreFlightLinter) Description() string {
	return "We must be able to install the preflight daemonset in the same " +
		"namespace next to an existing Cilium installation. So, by disabling the agent, " +
		"nodeinit, and operator, and enabling preflight, there should be no overlapping Kubernetes resources."
}

func (p *PreFlightLinter) Lint(chartPath string, values []string) error {
	getAllObjs := func(withPreflight bool) (sets.Set[string], error) {
		v := append([]string{}, values...)
		if withPreflight {
			v = append(v, "preflight.enabled=true", "config.enabled=false",
				"agent=false", "nodeinit.enabled=false", "operator.enabled=false")
		} else {
			v = append(v, "preflight.enabled=false")
		}

		name := "cilium"
		if withPreflight {
			name = "cilium-prefight"
		}

		objs, err := render(name, chartPath, v)
		if err != nil {
			return nil, err
		}

		out := sets.New[string]()

		for _, obj := range objs {
			key := fmt.Sprintf("<%s %s/%s>",
				obj.GetObjectKind().GroupVersionKind().GroupKind(),
				obj.GetNamespace(),
				obj.GetName())
			if out.Has(key) {
				return nil, fmt.Errorf("object %s is duplicated", key)
			}

			out.Insert(key)
		}

		return out, nil
	}

	objsNoPreflight, err := getAllObjs(false)
	if err != nil {
		return fmt.Errorf("failed to render without preflight: %w", err)
	}

	objsWithPreflight, err := getAllObjs(true)
	if err != nil {
		return fmt.Errorf("failed to render with preflight: %w", err)
	}

	// compute the union, it should be empty
	overlap := objsNoPreflight.Intersection(objsWithPreflight)

	if len(overlap) > 0 {
		return fmt.Errorf("colliding objects when when preflight is disabled and enabled: %v",
			overlap.UnsortedList())
	}

	return nil
}
