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
	"strings"
)

// NonVendorPath returns a package path that does not include anything before the
// last vendor directory.  This is useful for when using vendor directories,
// and using go/types.Package.Path(), which returns the full path including vendor.
//
// If you're using this, make sure you really need it -- it's better to index by
// the actual Package object when you can.
func NonVendorPath(rawPath string) string {
	parts := strings.Split(rawPath, "/vendor/")
	return parts[len(parts)-1]
}
