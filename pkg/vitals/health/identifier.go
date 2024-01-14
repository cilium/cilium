package health

import (
	"strings"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/statedb/index"
)

type Identifier struct {
	ModuleID    cell.FullModuleID
	ComponentID []string
}

func (i Identifier) String() string {
	return i.ModuleID.String() + "." + strings.Join(i.ComponentID, ".")
}

func (i Identifier) Key() index.Key {
	return []byte(i.String())
}
