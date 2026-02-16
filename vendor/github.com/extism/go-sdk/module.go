package extism

import "github.com/tetratelabs/wazero/api"

// Module is a wrapper around a wazero module. It allows us to provide
// our own API and stability guarantees despite any changes that wazero
// may choose to make.
type Module struct {
	inner api.Module
}

// ExportedFunctions returns a map of functions exported from the module
// keyed by the function name.
func (m *Module) ExportedFunctions() map[string]FunctionDefinition {
	v := make(map[string]FunctionDefinition)
	for name, def := range m.inner.ExportedFunctionDefinitions() {
		v[name] = FunctionDefinition{inner: def}
	}
	return v
}

// FunctionDefinition represents a function defined in a module. It provides
// a wrapper around the underlying wazero function definition.
type FunctionDefinition struct {
	inner api.FunctionDefinition
}

func (f *FunctionDefinition) Name() string {
	return f.inner.Name()
}
