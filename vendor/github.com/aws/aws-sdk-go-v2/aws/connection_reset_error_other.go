// +build appengine plan9

package aws

import (
	"strings"
)

func isErrConnectionReset(err error) bool {
	return strings.Contains(err.Error(), "connection reset")
}
