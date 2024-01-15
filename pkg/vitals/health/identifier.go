package health

import (
	"strings"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb/index"
)

// Identifier is a unique identifier for a health reporter, it is a composition of
// two parts: the module ID, and the component ID.
type Identifier struct {
	ModuleID    cell.FullModuleID
	ComponentID []string
}

func NewIdentifier(id cell.FullModuleID, componentID ...string) Identifier {
	return Identifier{
		ModuleID:    id,
		ComponentID: componentID,
	}
}

func (i Identifier) withSubComponent(componentID string) Identifier {
	return Identifier{
		ModuleID:    i.ModuleID,
		ComponentID: append(i.ComponentID, componentID),
	}
}

func (i Identifier) component() string {
	return strings.Join(i.ComponentID, ".")
}

func (i Identifier) module() string {
	return string(i.ModuleID.String())
}

func (i Identifier) String() string {
	return i.module() + "." + i.component()
}

func (i Identifier) Key() index.Key {
	return []byte(i.String())
}
