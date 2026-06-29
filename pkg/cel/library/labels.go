// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package library

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/ast"
	celTypes "github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/cilium/cilium/pkg/cel/types"
	"github.com/cilium/cilium/pkg/labels"
)

const (
	LabelMatcherVar      string = "@label_matcher"
	LabelLookupMacroName string = "label"

	LabelMatcherLookupFuncName      string = "__label_matcher_lookup__"
	LabelMatcherLookupKeyFuncName   string = "__label_matcher_lookup_key__"
	LabelMatcherLookupLabelFuncName string = "__label_matcher_lookup_label__"

	LabelMakeFuncName string = "__label_make__"
)

func LabelMatcher() cel.EnvOption {
	return cel.Lib(labelMatcherLib)
}

var labelMatcherLib = &labelMatcher{}

type labelMatcher struct{}

func (*labelMatcher) LibraryName() string {
	return "cilium.label"
}

func (*labelMatcher) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable(LabelMatcherVar, types.LabelMatcherType),
		// 'label' macro definition that looks up provided label key from label_matcher variable.
		cel.Macros(
			cel.GlobalMacro(
				LabelLookupMacroName,
				1,
				labelMacroExpander,
				cel.MacroDocs(
					"Looks up a label in the '@label_matcher' variable and returns optional(value).",
					"Returns optional.none() when the label is absent; optional.of(value) otherwise.",
				),
				cel.MacroExamples(
					`label("<source>:<key>")      // Looks up label value for <key> from @label_matcher variable with <source>`,
					`label("k8s:app")             // optional.of("myapp") when present`,
					`label("k8s:missing")         // optional.none()`,
					`label("k8s:app").hasValue()  // true`,
					`label("k8s:app").value()     // "myapp"`,
				),
			),
		),
		// Label matcher lookup internal functions.
		cel.Function(LabelMatcherLookupFuncName,
			cel.Overload(
				LabelMatcherLookupKeyFuncName,
				[]*cel.Type{types.LabelMatcherType, cel.StringType},
				cel.OptionalType(cel.StringType),
				cel.OverloadExamples(),
				cel.BinaryBinding(lookupLabelString),
			),
			cel.Overload(
				LabelMatcherLookupLabelFuncName,
				[]*cel.Type{types.LabelMatcherType, types.LabelType},
				cel.OptionalType(cel.StringType),
				cel.BinaryBinding(lookupLabelType),
			),
		),
		cel.Function(LabelMakeFuncName,
			cel.FunctionDocs(
				"Internal: constructs a cilium.Label from (source, key) string parts.",
				"Emitted by the label() macro for literal string arguments.",
				"Never called directly in user expressions.",
			),
			cel.Overload(
				LabelMakeFuncName,
				[]*cel.Type{cel.StringType, cel.StringType},
				types.LabelType,
				cel.BinaryBinding(makeLabel),
			),
		),
	}
}

// ProgramOptions returns the decorator that folds __label_make__ calls into constants
// at program creation time, eliminating all runtime overhead for literal label keys.
func (*labelMatcher) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

func lookupLabel(lm labels.LabelMatcher, lbl labels.Label) ref.Val {
	value, exists := lm.LookupLabel(&lbl)
	if !exists {
		return celTypes.OptionalNone
	}
	return celTypes.OptionalOf(celTypes.String(value))
}

// lookupLabelString looks up Label from LabelMatcher argument by first parsing the
// key as select label.
func lookupLabelString(lm, key ref.Val) ref.Val {
	matcher, ok := lm.Value().(labels.LabelMatcher)
	if !ok {
		return celTypes.NewErr("label() requires a LabelMatcher, got %T", lm.Value())
	}
	labelKey, ok := key.Value().(string)
	if !ok {
		return celTypes.NewErr("label() requires a string, got %T", key.Value())
	}
	lbl := labels.ParseSelectLabel(labelKey)
	return lookupLabel(matcher, lbl)
}

func lookupLabelType(lm, key ref.Val) ref.Val {
	matcher, ok := lm.Value().(labels.LabelMatcher)
	if !ok {
		return celTypes.NewErr("label() requires a LabelMatcher, got %T", lm.Value())
	}
	label, ok := key.(types.Label)
	if !ok {
		return celTypes.NewErr("label() requires a LabelType, got %T", key.Value())
	}
	return lookupLabel(matcher, label.Label)
}

// makeLabel constructs CEL Label type from provided source and key.
func makeLabel(source, key ref.Val) ref.Val {
	s, ok := source.Value().(string)
	if !ok {
		return celTypes.NewErr("source must be a string, got %T", source.Value())
	}
	k, ok := key.Value().(string)
	if !ok {
		return celTypes.NewErr("key must be a string, got %T", key.Value())
	}
	return types.Label{Label: labels.Label{Source: s, Key: k}}
}

// labelMacroExpander expands 'label' macro in CEL expression.
// For string literal arguments to macro
func labelMacroExpander(eh cel.MacroExprFactory, target ast.Expr, args []ast.Expr) (ast.Expr, *cel.Error) {
	if args[0].Kind() == ast.LiteralKind {
		if strVal, ok := args[0].AsLiteral().(celTypes.String); ok {
			lbl := labels.ParseSelectLabel(string(strVal))
			return eh.NewCall(
				LabelMatcherLookupFuncName,
				eh.NewIdent(LabelMatcherVar),
				eh.NewCall(
					LabelMakeFuncName,
					eh.NewLiteral(celTypes.String(lbl.Source)),
					eh.NewLiteral(celTypes.String(lbl.Key)),
				),
			), nil
		}
	}
	return eh.NewCall(LabelMatcherLookupFuncName, eh.NewIdent(LabelMatcherVar), args[0]), nil
}
