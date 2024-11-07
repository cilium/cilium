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

package markers

// ApplyPriority designates the order markers should be applied.
// Lower priority indicates it should be applied first
type ApplyPriority int64

const (
	// ApplyPriorityDefault is the default priority for markers
	// that don't implement ApplyPriorityMarker
	ApplyPriorityDefault ApplyPriority = 10

	// ApplyPriorityFirst is the priority value assigned to markers
	// that implement the ApplyFirst() method
	ApplyPriorityFirst ApplyPriority = 1
)

// ApplyPriorityMarker designates the order validation markers should be applied.
// Lower priority indicates it should be applied first
type ApplyPriorityMarker interface {
	ApplyPriority() ApplyPriority
}
