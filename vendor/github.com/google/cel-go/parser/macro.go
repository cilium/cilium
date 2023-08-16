// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package parser

import (
	"fmt"

	"github.com/google/cel-go/common"
	"github.com/google/cel-go/common/operators"

	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

// NewGlobalMacro creates a Macro for a global function with the specified arg count.
func NewGlobalMacro(function string, argCount int, expander MacroExpander) Macro {
	return &macro{
		function: function,
		argCount: argCount,
		expander: expander}
}

// NewReceiverMacro creates a Macro for a receiver function matching the specified arg count.
func NewReceiverMacro(function string, argCount int, expander MacroExpander) Macro {
	return &macro{
		function:      function,
		argCount:      argCount,
		expander:      expander,
		receiverStyle: true}
}

// NewGlobalVarArgMacro creates a Macro for a global function with a variable arg count.
func NewGlobalVarArgMacro(function string, expander MacroExpander) Macro {
	return &macro{
		function:    function,
		expander:    expander,
		varArgStyle: true}
}

// NewReceiverVarArgMacro creates a Macro for a receiver function matching a variable arg count.
func NewReceiverVarArgMacro(function string, expander MacroExpander) Macro {
	return &macro{
		function:      function,
		expander:      expander,
		receiverStyle: true,
		varArgStyle:   true}
}

// Macro interface for describing the function signature to match and the MacroExpander to apply.
//
// Note: when a Macro should apply to multiple overloads (based on arg count) of a given function,
// a Macro should be created per arg-count.
type Macro interface {
	// Function name to match.
	Function() string

	// ArgCount for the function call.
	//
	// When the macro is a var-arg style macro, the return value will be zero, but the MacroKey
	// will contain a `*` where the arg count would have been.
	ArgCount() int

	// IsReceiverStyle returns true if the macro matches a receiver style call.
	IsReceiverStyle() bool

	// MacroKey returns the macro signatures accepted by this macro.
	//
	// Format: `<function>:<arg-count>:<is-receiver>`.
	//
	// When the macros is a var-arg style macro, the `arg-count` value is represented as a `*`.
	MacroKey() string

	// Expander returns the MacroExpander to apply when the macro key matches the parsed call
	// signature.
	Expander() MacroExpander
}

// Macro type which declares the function name and arg count expected for the
// macro, as well as a macro expansion function.
type macro struct {
	function      string
	receiverStyle bool
	varArgStyle   bool
	argCount      int
	expander      MacroExpander
}

// Function returns the macro's function name (i.e. the function whose syntax it mimics).
func (m *macro) Function() string {
	return m.function
}

// ArgCount returns the number of arguments the macro expects.
func (m *macro) ArgCount() int {
	return m.argCount
}

// IsReceiverStyle returns whether the macro is receiver style.
func (m *macro) IsReceiverStyle() bool {
	return m.receiverStyle
}

// Expander implements the Macro interface method.
func (m *macro) Expander() MacroExpander {
	return m.expander
}

// MacroKey implements the Macro interface method.
func (m *macro) MacroKey() string {
	if m.varArgStyle {
		return makeVarArgMacroKey(m.function, m.receiverStyle)
	}
	return makeMacroKey(m.function, m.argCount, m.receiverStyle)
}

func makeMacroKey(name string, args int, receiverStyle bool) string {
	return fmt.Sprintf("%s:%d:%v", name, args, receiverStyle)
}

func makeVarArgMacroKey(name string, receiverStyle bool) string {
	return fmt.Sprintf("%s:*:%v", name, receiverStyle)
}

// MacroExpander converts a call and its associated arguments into a new CEL abstract syntax tree.
//
// If the MacroExpander determines within the implementation that an expansion is not needed it may return
// a nil Expr value to indicate a non-match. However, if an expansion is to be performed, but the arguments
// are not well-formed, the result of the expansion will be an error.
//
// The MacroExpander accepts as arguments a MacroExprHelper as well as the arguments used in the function call
// and produces as output an Expr ast node.
//
// Note: when the Macro.IsReceiverStyle() method returns true, the target argument will be nil.
type MacroExpander func(eh ExprHelper,
	target *exprpb.Expr,
	args []*exprpb.Expr) (*exprpb.Expr, *common.Error)

// ExprHelper assists with the manipulation of proto-based Expr values in a manner which is
// consistent with the source position and expression id generation code leveraged by both
// the parser and type-checker.
type ExprHelper interface {
	// Copy the input expression with a brand new set of identifiers.
	Copy(*exprpb.Expr) *exprpb.Expr

	// LiteralBool creates an Expr value for a bool literal.
	LiteralBool(value bool) *exprpb.Expr

	// LiteralBytes creates an Expr value for a byte literal.
	LiteralBytes(value []byte) *exprpb.Expr

	// LiteralDouble creates an Expr value for double literal.
	LiteralDouble(value float64) *exprpb.Expr

	// LiteralInt creates an Expr value for an int literal.
	LiteralInt(value int64) *exprpb.Expr

	// LiteralString creates am Expr value for a string literal.
	LiteralString(value string) *exprpb.Expr

	// LiteralUint creates an Expr value for a uint literal.
	LiteralUint(value uint64) *exprpb.Expr

	// NewList creates a CreateList instruction where the list is comprised of the optional set
	// of elements provided as arguments.
	NewList(elems ...*exprpb.Expr) *exprpb.Expr

	// NewMap creates a CreateStruct instruction for a map where the map is comprised of the
	// optional set of key, value entries.
	NewMap(entries ...*exprpb.Expr_CreateStruct_Entry) *exprpb.Expr

	// NewMapEntry creates a Map Entry for the key, value pair.
	NewMapEntry(key *exprpb.Expr, val *exprpb.Expr, optional bool) *exprpb.Expr_CreateStruct_Entry

	// NewObject creates a CreateStruct instruction for an object with a given type name and
	// optional set of field initializers.
	NewObject(typeName string, fieldInits ...*exprpb.Expr_CreateStruct_Entry) *exprpb.Expr

	// NewObjectFieldInit creates a new Object field initializer from the field name and value.
	NewObjectFieldInit(field string, init *exprpb.Expr, optional bool) *exprpb.Expr_CreateStruct_Entry

	// Fold creates a fold comprehension instruction.
	//
	// - iterVar is the iteration variable name.
	// - iterRange represents the expression that resolves to a list or map where the elements or
	//   keys (respectively) will be iterated over.
	// - accuVar is the accumulation variable name, typically parser.AccumulatorName.
	// - accuInit is the initial expression whose value will be set for the accuVar prior to
	//   folding.
	// - condition is the expression to test to determine whether to continue folding.
	// - step is the expression to evaluation at the conclusion of a single fold iteration.
	// - result is the computation to evaluate at the conclusion of the fold.
	//
	// The accuVar should not shadow variable names that you would like to reference within the
	// environment in the step and condition expressions. Presently, the name __result__ is commonly
	// used by built-in macros but this may change in the future.
	Fold(iterVar string,
		iterRange *exprpb.Expr,
		accuVar string,
		accuInit *exprpb.Expr,
		condition *exprpb.Expr,
		step *exprpb.Expr,
		result *exprpb.Expr) *exprpb.Expr

	// Ident creates an identifier Expr value.
	Ident(name string) *exprpb.Expr

	// AccuIdent returns an accumulator identifier for use with comprehension results.
	AccuIdent() *exprpb.Expr

	// GlobalCall creates a function call Expr value for a global (free) function.
	GlobalCall(function string, args ...*exprpb.Expr) *exprpb.Expr

	// ReceiverCall creates a function call Expr value for a receiver-style function.
	ReceiverCall(function string, target *exprpb.Expr, args ...*exprpb.Expr) *exprpb.Expr

	// PresenceTest creates a Select TestOnly Expr value for modelling has() semantics.
	PresenceTest(operand *exprpb.Expr, field string) *exprpb.Expr

	// Select create a field traversal Expr value.
	Select(operand *exprpb.Expr, field string) *exprpb.Expr

	// OffsetLocation returns the Location of the expression identifier.
	OffsetLocation(exprID int64) common.Location
}

var (
	// HasMacro expands "has(m.f)" which tests the presence of a field, avoiding the need to
	// specify the field as a string.
	HasMacro = NewGlobalMacro(operators.Has, 1, MakeHas)

	// AllMacro expands "range.all(var, predicate)" into a comprehension which ensures that all
	// elements in the range satisfy the predicate.
	AllMacro = NewReceiverMacro(operators.All, 2, MakeAll)

	// ExistsMacro expands "range.exists(var, predicate)" into a comprehension which ensures that
	// some element in the range satisfies the predicate.
	ExistsMacro = NewReceiverMacro(operators.Exists, 2, MakeExists)

	// ExistsOneMacro expands "range.exists_one(var, predicate)", which is true if for exactly one
	// element in range the predicate holds.
	ExistsOneMacro = NewReceiverMacro(operators.ExistsOne, 2, MakeExistsOne)

	// MapMacro expands "range.map(var, function)" into a comprehension which applies the function
	// to each element in the range to produce a new list.
	MapMacro = NewReceiverMacro(operators.Map, 2, MakeMap)

	// MapFilterMacro expands "range.map(var, predicate, function)" into a comprehension which
	// first filters the elements in the range by the predicate, then applies the transform function
	// to produce a new list.
	MapFilterMacro = NewReceiverMacro(operators.Map, 3, MakeMap)

	// FilterMacro expands "range.filter(var, predicate)" into a comprehension which filters
	// elements in the range, producing a new list from the elements that satisfy the predicate.
	FilterMacro = NewReceiverMacro(operators.Filter, 2, MakeFilter)

	// AllMacros includes the list of all spec-supported macros.
	AllMacros = []Macro{
		HasMacro,
		AllMacro,
		ExistsMacro,
		ExistsOneMacro,
		MapMacro,
		MapFilterMacro,
		FilterMacro,
	}

	// NoMacros list.
	NoMacros = []Macro{}
)

// AccumulatorName is the traditional variable name assigned to the fold accumulator variable.
const AccumulatorName = "__result__"

type quantifierKind int

const (
	quantifierAll quantifierKind = iota
	quantifierExists
	quantifierExistsOne
)

// MakeAll expands the input call arguments into a comprehension that returns true if all of the
// elements in the range match the predicate expressions:
// <iterRange>.all(<iterVar>, <predicate>)
func MakeAll(eh ExprHelper, target *exprpb.Expr, args []*exprpb.Expr) (*exprpb.Expr, *common.Error) {
	return makeQuantifier(quantifierAll, eh, target, args)
}

// MakeExists expands the input call arguments into a comprehension that returns true if any of the
// elements in the range match the predicate expressions:
// <iterRange>.exists(<iterVar>, <predicate>)
func MakeExists(eh ExprHelper, target *exprpb.Expr, args []*exprpb.Expr) (*exprpb.Expr, *common.Error) {
	return makeQuantifier(quantifierExists, eh, target, args)
}

// MakeExistsOne expands the input call arguments into a comprehension that returns true if exactly
// one of the elements in the range match the predicate expressions:
// <iterRange>.exists_one(<iterVar>, <predicate>)
func MakeExistsOne(eh ExprHelper, target *exprpb.Expr, args []*exprpb.Expr) (*exprpb.Expr, *common.Error) {
	return makeQuantifier(quantifierExistsOne, eh, target, args)
}

// MakeMap expands the input call arguments into a comprehension that transforms each element in the
// input to produce an output list.
//
// There are two call patterns supported by map:
//
//	<iterRange>.map(<iterVar>, <transform>)
//	<iterRange>.map(<iterVar>, <predicate>, <transform>)
//
// In the second form only iterVar values which return true when provided to the predicate expression
// are transformed.
func MakeMap(eh ExprHelper, target *exprpb.Expr, args []*exprpb.Expr) (*exprpb.Expr, *common.Error) {
	v, found := extractIdent(args[0])
	if !found {
		return nil, &common.Error{Message: "argument is not an identifier"}
	}

	var fn *exprpb.Expr
	var filter *exprpb.Expr

	if len(args) == 3 {
		filter = args[1]
		fn = args[2]
	} else {
		filter = nil
		fn = args[1]
	}

	accuExpr := eh.Ident(AccumulatorName)
	init := eh.NewList()
	condition := eh.LiteralBool(true)
	step := eh.GlobalCall(operators.Add, accuExpr, eh.NewList(fn))

	if filter != nil {
		step = eh.GlobalCall(operators.Conditional, filter, step, accuExpr)
	}
	return eh.Fold(v, target, AccumulatorName, init, condition, step, accuExpr), nil
}

// MakeFilter expands the input call arguments into a comprehension which produces a list which contains
// only elements which match the provided predicate expression:
// <iterRange>.filter(<iterVar>, <predicate>)
func MakeFilter(eh ExprHelper, target *exprpb.Expr, args []*exprpb.Expr) (*exprpb.Expr, *common.Error) {
	v, found := extractIdent(args[0])
	if !found {
		return nil, &common.Error{Message: "argument is not an identifier"}
	}

	filter := args[1]
	accuExpr := eh.Ident(AccumulatorName)
	init := eh.NewList()
	condition := eh.LiteralBool(true)
	step := eh.GlobalCall(operators.Add, accuExpr, eh.NewList(args[0]))
	step = eh.GlobalCall(operators.Conditional, filter, step, accuExpr)
	return eh.Fold(v, target, AccumulatorName, init, condition, step, accuExpr), nil
}

// MakeHas expands the input call arguments into a presence test, e.g. has(<operand>.field)
func MakeHas(eh ExprHelper, target *exprpb.Expr, args []*exprpb.Expr) (*exprpb.Expr, *common.Error) {
	if s, ok := args[0].ExprKind.(*exprpb.Expr_SelectExpr); ok {
		return eh.PresenceTest(s.SelectExpr.GetOperand(), s.SelectExpr.GetField()), nil
	}
	return nil, &common.Error{Message: "invalid argument to has() macro"}
}

func makeQuantifier(kind quantifierKind, eh ExprHelper, target *exprpb.Expr, args []*exprpb.Expr) (*exprpb.Expr, *common.Error) {
	v, found := extractIdent(args[0])
	if !found {
		location := eh.OffsetLocation(args[0].GetId())
		return nil, &common.Error{
			Message:  "argument must be a simple name",
			Location: location,
		}
	}

	var init *exprpb.Expr
	var condition *exprpb.Expr
	var step *exprpb.Expr
	var result *exprpb.Expr
	switch kind {
	case quantifierAll:
		init = eh.LiteralBool(true)
		condition = eh.GlobalCall(operators.NotStrictlyFalse, eh.AccuIdent())
		step = eh.GlobalCall(operators.LogicalAnd, eh.AccuIdent(), args[1])
		result = eh.AccuIdent()
	case quantifierExists:
		init = eh.LiteralBool(false)
		condition = eh.GlobalCall(
			operators.NotStrictlyFalse,
			eh.GlobalCall(operators.LogicalNot, eh.AccuIdent()))
		step = eh.GlobalCall(operators.LogicalOr, eh.AccuIdent(), args[1])
		result = eh.AccuIdent()
	case quantifierExistsOne:
		zeroExpr := eh.LiteralInt(0)
		oneExpr := eh.LiteralInt(1)
		init = zeroExpr
		condition = eh.LiteralBool(true)
		step = eh.GlobalCall(operators.Conditional, args[1],
			eh.GlobalCall(operators.Add, eh.AccuIdent(), oneExpr), eh.AccuIdent())
		result = eh.GlobalCall(operators.Equals, eh.AccuIdent(), oneExpr)
	default:
		return nil, &common.Error{Message: fmt.Sprintf("unrecognized quantifier '%v'", kind)}
	}
	return eh.Fold(v, target, AccumulatorName, init, condition, step, result), nil
}

func extractIdent(e *exprpb.Expr) (string, bool) {
	switch e.ExprKind.(type) {
	case *exprpb.Expr_IdentExpr:
		return e.GetIdentExpr().GetName(), true
	}
	return "", false
}
