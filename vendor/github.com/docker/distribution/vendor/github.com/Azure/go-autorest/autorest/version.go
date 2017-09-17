package autorest

import (
	"fmt"
)

const (
	major        = "7"
	minor        = "3"
	patch        = "0"
	tag          = ""
	semVerFormat = "%s.%s.%s%s"
)

var version string

// Version returns the semantic version (see http://semver.org).
func Version() string {
	if version == "" {
		version = fmt.Sprintf(semVerFormat, major, minor, patch, tag)
	}
	return version
}
