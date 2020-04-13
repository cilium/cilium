// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package regeneration

import (
	"context"
)

// DatapathRegenerationLevel determines what is expected of the datapath when
// a regeneration event is processed.
type DatapathRegenerationLevel int

const (
	// Invalid is the default level to enforce explicit setting of
	// the regeneration level.
	Invalid DatapathRegenerationLevel = iota
	// RegenerateWithoutDatapath indicates that datapath rebuild or reload
	// is not required to implement this regeneration.
	RegenerateWithoutDatapath
	// RegenerateWithDatapathLoad indicates that the datapath must be
	// reloaded but not recompiled to implement this regeneration.
	RegenerateWithDatapathLoad
	// RegenerateWithDatapathRewrite indicates that the datapath must be
	// recompiled and reloaded to implement this regeneration.
	RegenerateWithDatapathRewrite
	// RegenerateWithDatapathRebuild indicates that the datapath must be
	// fully recompiled and reloaded without using any cached templates.
	RegenerateWithDatapathRebuild
)

// String converts a DatapathRegenerationLevel into a human-readable string.
func (r DatapathRegenerationLevel) String() string {
	switch r {
	case Invalid:
		return "invalid"
	case RegenerateWithoutDatapath:
		return "no-rebuild"
	case RegenerateWithDatapathLoad:
		return "reload"
	case RegenerateWithDatapathRewrite:
		return "rewrite+load"
	case RegenerateWithDatapathRebuild:
		return "compile+load"
	default:
		break
	}
	return "BUG: Unknown DatapathRegenerationLevel"
}

// ExternalRegenerationMetadata contains any information about a regeneration that
// the endpoint subsystem should be made aware of for a given endpoint.
type ExternalRegenerationMetadata struct {
	// Reason provides context to source for the regeneration, which is
	// used to generate useful log messages.
	Reason string

	// RegenerationLevel forces datapath regeneration according to the
	// levels defined in the DatapathRegenerationLevel description.
	RegenerationLevel DatapathRegenerationLevel

	ParentContext context.Context
}
