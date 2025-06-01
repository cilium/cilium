/*
Copyright The ORAS Authors.
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

package oras

import "oras.land/oras-go/v2/content"

// Target is a CAS with generic tags.
type Target interface {
	content.Storage
	content.TagResolver
}

// GraphTarget is a CAS with generic tags that supports direct predecessor node
// finding.
type GraphTarget interface {
	content.GraphStorage
	content.TagResolver
}

// ReadOnlyTarget represents a read-only Target.
type ReadOnlyTarget interface {
	content.ReadOnlyStorage
	content.Resolver
}

// ReadOnlyGraphTarget represents a read-only GraphTarget.
type ReadOnlyGraphTarget interface {
	content.ReadOnlyGraphStorage
	content.Resolver
}
