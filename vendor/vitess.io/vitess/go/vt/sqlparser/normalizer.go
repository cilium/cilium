// Copyright 2016, Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sqlparser

import (
	"fmt"

	"github.com/youtube/vitess/go/sqltypes"
	querypb "github.com/youtube/vitess/go/vt/proto/query"
)

// Normalize changes the statement to use bind values, and
// updates the bind vars to those values. The supplied prefix
// is used to generate the bind var names. The function ensures
// that there are no collisions with existing bind vars.
func Normalize(stmt Statement, bindVars map[string]interface{}, prefix string) {
	reserved := GetBindvars(stmt)
	// vals allows us to reuse bindvars for
	// identical values.
	counter := 1
	vals := make(map[string]string)
	_ = Walk(func(node SQLNode) (kontinue bool, err error) {
		switch node := node.(type) {
		case *SQLVal:
			// Make the bindvar
			bval := sqlToBindvar(node)
			if bval == nil {
				// If unsuccessful continue.
				return true, nil
			}
			// Check if there's a bindvar for that value already.
			var key string
			if bval.Type == sqltypes.VarBinary {
				// Prefixing strings with "'" ensures that a string
				// and number that have the same representation don't
				// collide.
				key = "'" + string(node.Val)
			} else {
				key = string(node.Val)
			}
			bvname, ok := vals[key]
			if !ok {
				// If there's no such bindvar, make a new one.
				bvname, counter = newName(prefix, counter, reserved)
				vals[key] = bvname
				bindVars[bvname] = bval
			}
			// Modify the AST node to a bindvar.
			node.Type = ValArg
			node.Val = append([]byte(":"), bvname...)
		case *ComparisonExpr:
			switch node.Operator {
			case InStr, NotInStr:
			default:
				return true, nil
			}
			// It's either IN or NOT IN.
			tupleVals, ok := node.Right.(ValTuple)
			if !ok {
				return true, nil
			}
			// The RHS is a tuple of values.
			// Make a list bindvar.
			bvals := &querypb.BindVariable{
				Type: sqltypes.Tuple,
			}
			for _, val := range tupleVals {
				bval := sqlToBindvar(val)
				if bval == nil {
					return true, nil
				}
				bvals.Values = append(bvals.Values, &querypb.Value{
					Type:  bval.Type,
					Value: bval.Value,
				})
			}
			var bvname string
			bvname, counter = newName(prefix, counter, reserved)
			bindVars[bvname] = bvals
			// Modify RHS to be a list bindvar.
			node.Right = ListArg(append([]byte("::"), bvname...))
		}
		return true, nil
	}, stmt)
}

func sqlToBindvar(node SQLNode) *querypb.BindVariable {
	if node, ok := node.(*SQLVal); ok {
		switch node.Type {
		case StrVal:
			return &querypb.BindVariable{Type: sqltypes.VarBinary, Value: node.Val}
		case IntVal:
			return &querypb.BindVariable{Type: sqltypes.Int64, Value: node.Val}
		case FloatVal:
			return &querypb.BindVariable{Type: sqltypes.Float64, Value: node.Val}
		}
	}
	return nil
}

func newName(prefix string, counter int, reserved map[string]struct{}) (string, int) {
	for {
		newName := fmt.Sprintf("%s%d", prefix, counter)
		if _, ok := reserved[newName]; !ok {
			reserved[newName] = struct{}{}
			return newName, counter + 1
		}
		counter++
	}
}

// GetBindvars returns a map of the bind vars referenced in the statement.
// TODO(sougou); This function gets called again from vtgate/planbuilder.
// Ideally, this should be done only once.
func GetBindvars(stmt Statement) map[string]struct{} {
	bindvars := make(map[string]struct{})
	_ = Walk(func(node SQLNode) (kontinue bool, err error) {
		switch node := node.(type) {
		case *SQLVal:
			if node.Type == ValArg {
				bindvars[string(node.Val[1:])] = struct{}{}
			}
		case ListArg:
			bindvars[string(node[2:])] = struct{}{}
		}
		return true, nil
	}, stmt)
	return bindvars
}
