// Copyright 2012 James Cooper. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package gorp

import (
	"fmt"
)

// A non-fatal error, when a select query returns columns that do not exist
// as fields in the struct it is being mapped to
// TODO: discuss wether this needs an error. encoding/json silently ignores missing fields
type NoFieldInTypeError struct {
	TypeName        string
	MissingColNames []string
}

func (err *NoFieldInTypeError) Error() string {
	return fmt.Sprintf("gorp: no fields %+v in type %s", err.MissingColNames, err.TypeName)
}

// returns true if the error is non-fatal (ie, we shouldn't immediately return)
func NonFatalError(err error) bool {
	switch err.(type) {
	case *NoFieldInTypeError:
		return true
	default:
		return false
	}
}
