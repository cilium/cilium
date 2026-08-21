// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

var (
	// LabelMatcherType is the opaque CEL type used to represent labels.LabelMatcher.
	// OpaqueType signals to the type-checker that this is an external type with no
	// field-accessible structure; it can only be passed as a function argument.
	LabelMatcherType = cel.OpaqueType("cilium.LabelMatcher")

	// LabelType is the opaque CEL type used to represent labels.Label
	LabelType = cel.OpaqueType("cilium.Label")
)

// LabelMatcher provides a CEL representation of labels.LabelMatcher and implements ref.Val.
type LabelMatcher struct {
	labels.LabelMatcher
}

func NewLabelMatcher(m labels.LabelMatcher) LabelMatcher {
	return LabelMatcher{LabelMatcher: m}
}

func (LabelMatcher) ConvertToNative(_ reflect.Type) (any, error) {
	return nil, errors.New("type conversion not supported for cilium.LabelMatcher")
}

func (LabelMatcher) ConvertToType(_ ref.Type) ref.Val {
	return types.NewErr("type conversion not supported for cilium.LabelMatcher")
}

func (v LabelMatcher) Equal(other ref.Val) ref.Val {
	if o, ok := other.(LabelMatcher); ok {
		return types.Bool(v.LabelMatcher == o.LabelMatcher)
	}
	return types.ValOrErr(other, "no such overload")
}

func (LabelMatcher) Type() ref.Type {
	return LabelMatcherType
}

func (v LabelMatcher) Value() any {
	return v.LabelMatcher
}

// Label provides a CEL representation of labels.Label and implements ref.Val.
type Label struct {
	labels.Label
}

func (l Label) ConvertToNative(typeDesc reflect.Type) (any, error) {
	if reflect.TypeFor[labels.Label]().AssignableTo(typeDesc) {
		return l.Label, nil
	}
	if reflect.TypeFor[string]().AssignableTo(typeDesc) {
		return l.Label.String(), nil
	}
	return nil, fmt.Errorf("type conversion error from 'Label' to '%v'", typeDesc)
}

func (l Label) ConvertToType(typeVal ref.Type) ref.Val {
	switch typeVal {
	case LabelType:
		return l
	case types.TypeType:
		return LabelType
	case types.StringType:
		return types.String(l.Label.String())
	}
	return types.NewErr("type conversion error from '%s' to '%s'", LabelType, typeVal)
}

func (l Label) Equal(other ref.Val) ref.Val {
	if o, ok := other.(Label); ok {
		return types.Bool(l.Label.DeepEqual(&o.Label))
	}
	return types.ValOrErr(other, "no such overload")
}

func (v Label) Type() ref.Type {
	return LabelType
}

func (v Label) Value() any {
	return v.Label
}
