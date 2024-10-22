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

package markers

import (
	"fmt"
	"sync"
)

// Registry keeps track of registered definitions, and allows for easy lookup.
// It's thread-safe, and the zero-value can be safely used.
type Registry struct {
	forPkg   map[string]*Definition
	forType  map[string]*Definition
	forField map[string]*Definition
	helpFor  map[*Definition]*DefinitionHelp

	mu       sync.RWMutex
	initOnce sync.Once
}

func (r *Registry) init() {
	r.initOnce.Do(func() {
		if r.forPkg == nil {
			r.forPkg = make(map[string]*Definition)
		}
		if r.forType == nil {
			r.forType = make(map[string]*Definition)
		}
		if r.forField == nil {
			r.forField = make(map[string]*Definition)
		}
		if r.helpFor == nil {
			r.helpFor = make(map[*Definition]*DefinitionHelp)
		}
	})
}

// Define defines a new marker with the given name, target, and output type.
// It's a shortcut around
//
//	r.Register(MakeDefinition(name, target, obj))
func (r *Registry) Define(name string, target TargetType, obj interface{}) error {
	def, err := MakeDefinition(name, target, obj)
	if err != nil {
		return err
	}
	return r.Register(def)
}

// Register registers the given marker definition with this registry for later lookup.
func (r *Registry) Register(def *Definition) error {
	r.init()

	r.mu.Lock()
	defer r.mu.Unlock()

	switch def.Target {
	case DescribesPackage:
		r.forPkg[def.Name] = def
	case DescribesType:
		r.forType[def.Name] = def
	case DescribesField:
		r.forField[def.Name] = def
	default:
		return fmt.Errorf("unknown target type %v", def.Target)
	}
	return nil
}

// AddHelp stores the given help in the registry, marking it as associated with
// the given definition.
func (r *Registry) AddHelp(def *Definition, help *DefinitionHelp) {
	r.init()

	r.mu.Lock()
	defer r.mu.Unlock()

	r.helpFor[def] = help
}

// Lookup fetches the definition corresponding to the given name and target type.
func (r *Registry) Lookup(name string, target TargetType) *Definition {
	r.init()

	r.mu.RLock()
	defer r.mu.RUnlock()

	switch target {
	case DescribesPackage:
		return tryAnonLookup(name, r.forPkg)
	case DescribesType:
		return tryAnonLookup(name, r.forType)
	case DescribesField:
		return tryAnonLookup(name, r.forField)
	default:
		return nil
	}
}

// HelpFor fetches the help for a given definition, if present.
func (r *Registry) HelpFor(def *Definition) *DefinitionHelp {
	r.init()

	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.helpFor[def]
}

// AllDefinitions returns all marker definitions known to this registry.
func (r *Registry) AllDefinitions() []*Definition {
	res := make([]*Definition, 0, len(r.forPkg)+len(r.forType)+len(r.forField))
	for _, def := range r.forPkg {
		res = append(res, def)
	}
	for _, def := range r.forType {
		res = append(res, def)
	}
	for _, def := range r.forField {
		res = append(res, def)
	}
	return res
}

// tryAnonLookup tries looking up the given marker as both an struct-based
// marker and an anonymous marker, returning whichever format matches first,
// preferring the longer (anonymous) name in case of conflicts.
func tryAnonLookup(name string, defs map[string]*Definition) *Definition {
	// NB(directxman12): we look up anonymous names first to work with
	// legacy style marker definitions that have a namespaced approach
	// (e.g. deepcopy-gen, which uses `+k8s:deepcopy-gen=foo,bar` *and*
	// `+k8s.io:deepcopy-gen:interfaces=foo`).
	name, anonName, _ := splitMarker(name)
	if def, exists := defs[anonName]; exists {
		return def
	}

	return defs[name]
}
