package btf

import "fmt"

// walkType calls fn on each child of typ.
func walkType(typ Type, fn func(*Type)) {
	// Explicitly type switch on the most common types to allow the inliner to
	// do its work. This avoids allocating intermediate slices from walk() on
	// the heap.
	switch v := typ.(type) {
	case *Void, *Int, *Enum, *Fwd, *Float:
		// No children to traverse.
	case *Pointer:
		fn(&v.Target)
	case *Array:
		fn(&v.Index)
		fn(&v.Type)
	case *Struct:
		for i := range v.Members {
			fn(&v.Members[i].Type)
		}
	case *Union:
		for i := range v.Members {
			fn(&v.Members[i].Type)
		}
	case *Typedef:
		fn(&v.Type)
	case *Volatile:
		fn(&v.Type)
	case *Const:
		fn(&v.Type)
	case *Restrict:
		fn(&v.Type)
	case *Func:
		fn(&v.Type)
	case *FuncProto:
		fn(&v.Return)
		for i := range v.Params {
			fn(&v.Params[i].Type)
		}
	case *Var:
		fn(&v.Type)
	case *Datasec:
		for i := range v.Vars {
			fn(&v.Vars[i].Type)
		}
	case *declTag:
		fn(&v.Type)
	case *typeTag:
		fn(&v.Type)
	case *cycle:
		// cycle has children, but we ignore them deliberately.
	default:
		panic(fmt.Sprintf("don't know how to walk Type %T", v))
	}
}
