// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logfields

import (
	"fmt"
)

// Repr formats an object with the Printf %+v formatter
func Repr(s interface{}) string {
	return fmt.Sprintf("%+v", s)
}
