// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package api

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/cilium/cilium/pkg/hubble/metrics/pathtemplate"
)

// OnMiss actions. An empty action means OnMissEmit.
const (
	OnMissEmit       = "emit"
	OnMissDropSample = "drop_sample"
)

// Static hubble-metrics option keys that configure PathContext, lowercased.
const (
	pathOptionKey         = "path"
	onMissActionOptionKey = "onmiss.action"
	onMissValueOptionKey  = "onmiss.value"
)

func isPathContextOptionKey(name string) bool {
	switch strings.ToLower(name) {
	case pathOptionKey, onMissActionOptionKey, onMissValueOptionKey:
		return true
	}
	return false
}

// PathContext adds a "path" label to the HTTP metrics, set to the first
// template that matches the request path.
type PathContext struct {
	Templates []string     `json:"templates,omitempty" yaml:"templates,omitempty"`
	OnMiss    OnMissPolicy `json:"onMiss,omitzero" yaml:"onMiss,omitempty"`
}

// OnMissPolicy says what happens to a sample whose path matches no template.
type OnMissPolicy struct {
	Action string `json:"action,omitempty" yaml:"action,omitempty"`
	// Value is ignored under OnMissDropSample.
	Value string `json:"value,omitempty" yaml:"value,omitempty"`
}

// DropOnMiss reports whether unmatched samples are dropped.
func (p *PathContext) DropOnMiss() bool {
	return p.OnMiss.Action == OnMissDropSample
}

// CompilePathContext validates PathContext and compiles its templates. It
// returns nil, nil when PathContext is unset. Both config sources go through
// it, so they reject the same configs.
func (m *MetricConfig) CompilePathContext() (*pathtemplate.Matcher, error) {
	var errs []error

	// Only the dynamic config can leave these here, and ParseContextOptions
	// would silently ignore them.
	for _, opt := range m.ContextOptionConfigs {
		if isPathContextOptionKey(opt.Name) {
			errs = append(errs, fmt.Errorf("option %q is not a context option, set it under pathContext", opt.Name))
		}
	}

	p := m.PathContext
	if p == nil {
		return nil, errors.Join(errs...)
	}

	matcher, err := pathtemplate.Compile(p.Templates)
	if err != nil {
		errs = append(errs, fmt.Errorf("pathContext.templates: %w", err))
	}

	switch p.OnMiss.Action {
	case "", OnMissEmit:
		// Skipped on a compile error, or an empty template is reported twice.
		if err == nil && slices.Contains(p.Templates, p.OnMiss.Value) {
			errs = append(errs, fmt.Errorf("pathContext.onMiss.value %q is also a template", p.OnMiss.Value))
		}
	case OnMissDropSample:
	default:
		errs = append(errs, fmt.Errorf("pathContext.onMiss.action %q is not one of %q, %q", p.OnMiss.Action, OnMissEmit, OnMissDropSample))
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return matcher, nil
}

// liftPathContextOption applies a static path or onMiss option to pathCtx,
// allocating it if nil, and reports whether the option was one. It keeps the
// raw value because parseOptionValues drops empty elements, which would make
// "onMiss.value=" unwritable and hide a stray "|". A repeated key overwrites
// the earlier one.
func liftPathContextOption(pathCtx *PathContext, name, value string) (*PathContext, bool) {
	key := strings.ToLower(name)
	if !isPathContextOptionKey(key) {
		return pathCtx, false
	}
	if pathCtx == nil {
		pathCtx = &PathContext{}
	}
	switch key {
	case pathOptionKey:
		pathCtx.Templates = strings.Split(value, "|")
	case onMissActionOptionKey:
		pathCtx.OnMiss.Action = value
	case onMissValueOptionKey:
		pathCtx.OnMiss.Value = value
	}
	return pathCtx, true
}
