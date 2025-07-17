//go:build !windows

package main

import (
	"flag"
	"go/build/constraint"
)

// buildTags is a comma-separated list of build tags.
//
// This follows the pre-Go 1.17 syntax and is kept for compatibility reasons.
type buildTags struct {
	Expr constraint.Expr
}

var _ flag.Value = (*buildTags)(nil)

func (bt *buildTags) String() string {
	if bt.Expr == nil {
		return ""
	}

	return (bt.Expr).String()
}

func (bt *buildTags) Set(value string) error {
	ct, err := constraint.Parse("// +build " + value)
	if err != nil {
		return err
	}

	bt.Expr = ct
	return nil
}

func andConstraints(x, y constraint.Expr) constraint.Expr {
	if x == nil {
		return y
	}

	if y == nil {
		return x
	}

	return &constraint.AndExpr{X: x, Y: y}
}
