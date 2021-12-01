// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package v2

var (
	// ErrEmptyCNP is an error representing a CNP that is empty, which means it is
	// missing both a `spec` and `specs` (both are nil).
	ErrEmptyCNP = NewErrParse("Invalid CiliumNetworkPolicy spec(s): empty policy")

	// ErrEmptyCCNP is an error representing a CCNP that is empty, which means it is
	// missing both a `spec` and `specs` (both are nil).
	ErrEmptyCCNP = NewErrParse("Invalid CiliumClusterwideNetworkPolicy spec(s): empty policy")

	// ParsingErr is for comparison when checking error types.
	ParsingErr = NewErrParse("")
)

// ErrParse is an error to describe where policy fails to parse due any invalid
// rule.
//
// +k8s:deepcopy-gen=false
// +deepequal-gen=false
type ErrParse struct {
	msg string
}

// NewErrParse returns a new ErrParse.
func NewErrParse(msg string) ErrParse {
	return ErrParse{
		msg: msg,
	}
}

// Error returns the error message for parsing
func (e ErrParse) Error() string {
	return e.msg
}

// Is returns true if the given error is the type of 'ErrParse'.
func (_ ErrParse) Is(e error) bool {
	_, ok := e.(ErrParse)
	return ok
}
