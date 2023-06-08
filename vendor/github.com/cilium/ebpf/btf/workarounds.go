package btf

// datasecResolveWorkaround ensures that certain vars in a Datasec are added
// to a Spec before the Datasec. This avoids a bug in kernel BTF validation.
//
// See https://lore.kernel.org/bpf/20230302123440.1193507-1-lmb@isovalent.com/
func datasecResolveWorkaround(spec *Spec, ds *Datasec) error {
	for _, vsi := range ds.Vars {
		v, ok := vsi.Type.(*Var)
		if !ok {
			continue
		}

		switch v.Type.(type) {
		case *Typedef, *Volatile, *Const, *Restrict, *typeTag:
			_, err := spec.Add(v.Type)
			if err != nil {
				return err
			}
		}
	}

	return nil
}
