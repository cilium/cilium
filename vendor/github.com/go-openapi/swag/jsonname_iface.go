// Copyright 2015 go-swagger maintainers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package swag

import (
	"github.com/go-openapi/swag/jsonname"
)

// DefaultJSONNameProvider is the default cache for types
//
// Deprecated: use [jsonname.DefaultJSONNameProvider] instead.
var DefaultJSONNameProvider = jsonname.DefaultJSONNameProvider

// NameProvider represents an object capable of translating from go property names
// to json property names.
//
// Deprecated: use [jsonname.NameProvider] instead.
type NameProvider = jsonname.NameProvider

// NewNameProvider creates a new name provider
//
// Deprecated: use [jsonname.NewNameProvider] instead.
func NewNameProvider() *NameProvider { return jsonname.NewNameProvider() }
