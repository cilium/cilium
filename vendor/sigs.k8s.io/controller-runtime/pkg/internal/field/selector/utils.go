/*
Copyright 2022 The Kubernetes Authors.

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

package selector

import (
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/selection"
)

// RequiresExactMatch checks if the given field selector is of the form `k=v` or `k==v`.
func RequiresExactMatch(sel fields.Selector) bool {
	reqs := sel.Requirements()
	if len(reqs) == 0 {
		return false
	}

	for _, req := range reqs {
		if req.Operator != selection.Equals && req.Operator != selection.DoubleEquals {
			return false
		}
	}
	return true
}
