/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package loader

import (
	"fmt"
	"go/ast"
	"go/token"
)

// PositionedError represents some error with an associated position.
// The position is tied to some external token.FileSet.
type PositionedError struct {
	Pos token.Pos
	error
}

// ErrFromNode returns the given error, with additional information
// attaching it to the given AST node.  It will automatically map
// over error lists.
func ErrFromNode(err error, node ast.Node) error {
	if asList, isList := err.(ErrList); isList {
		resList := make(ErrList, len(asList))
		for i, baseErr := range asList {
			resList[i] = ErrFromNode(baseErr, node)
		}
		return resList
	}
	return PositionedError{
		Pos:   node.Pos(),
		error: err,
	}
}

// MaybeErrList constructs an ErrList if the given list of
// errors has any errors, otherwise returning nil.
func MaybeErrList(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	return ErrList(errs)
}

// ErrList is a list of errors aggregated together into a single error.
type ErrList []error

func (l ErrList) Error() string {
	return fmt.Sprintf("%v", []error(l))
}
