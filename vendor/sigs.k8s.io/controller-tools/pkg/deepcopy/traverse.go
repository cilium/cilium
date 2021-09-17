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

package deepcopy

import (
	"fmt"
	"go/ast"
	"go/types"
	"io"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"sigs.k8s.io/controller-tools/pkg/loader"
	"sigs.k8s.io/controller-tools/pkg/markers"
)

// NB(directxman12): This code is a bit of a byzantine mess.
// I've tried to clean it up a bit from the original in deepcopy-gen,
// but parts remain a bit convoluted.  Exercise caution when changing.
// It's perhaps a tad over-commented now, but better safe than sorry.
// It also seriously needs auditing for sanity -- there's parts where we
// copy the original deepcopy-gen's output just to be safe, but some of that
// could be simplified away if we're careful.

// codeWriter assists in writing out Go code lines and blocks to a writer.
type codeWriter struct {
	out io.Writer
}

// Line writes a single line.
func (c *codeWriter) Line(line string) {
	fmt.Fprintln(c.out, line)
}

// Linef writes a single line with formatting (as per fmt.Sprintf).
func (c *codeWriter) Linef(line string, args ...interface{}) {
	fmt.Fprintf(c.out, line+"\n", args...)
}

// If writes an if statement with the given setup/condition clause, executing
// the given function to write the contents of the block.
func (c *codeWriter) If(setup string, block func()) {
	c.Linef("if %s {", setup)
	block()
	c.Line("}")
}

// If writes if and else statements with the given setup/condition clause, executing
// the given functions to write the contents of the blocks.
func (c *codeWriter) IfElse(setup string, ifBlock func(), elseBlock func()) {
	c.Linef("if %s {", setup)
	ifBlock()
	c.Line("} else {")
	elseBlock()
	c.Line("}")
}

// For writes an for statement with the given setup/condition clause, executing
// the given function to write the contents of the block.
func (c *codeWriter) For(setup string, block func()) {
	c.Linef("for %s {", setup)
	block()
	c.Line("}")
}

// importsList keeps track of required imports, automatically assigning aliases
// to import statement.
type importsList struct {
	byPath  map[string]string
	byAlias map[string]string

	pkg *loader.Package
}

// NeedImport marks that the given package is needed in the list of imports,
// returning the ident (import alias) that should be used to reference the package.
func (l *importsList) NeedImport(importPath string) string {
	// we get an actual path from Package, which might include venddored
	// packages if running on a package in vendor.
	if ind := strings.LastIndex(importPath, "/vendor/"); ind != -1 {
		importPath = importPath[ind+8: /* len("/vendor/") */]
	}

	// check to see if we've already assigned an alias, and just return that.
	alias, exists := l.byPath[importPath]
	if exists {
		return alias
	}

	// otherwise, calculate an import alias by joining path parts till we get something unique
	restPath, nextWord := path.Split(importPath)

	for otherPath, exists := "", true; exists && otherPath != importPath; otherPath, exists = l.byAlias[alias] {
		if restPath == "" {
			// do something else to disambiguate if we're run out of parts and
			// still have duplicates, somehow
			alias += "x"
		}

		// can't have a first digit, per Go identifier rules, so just skip them
		for firstRune, runeLen := utf8.DecodeRuneInString(nextWord); unicode.IsDigit(firstRune); firstRune, runeLen = utf8.DecodeRuneInString(nextWord) {
			nextWord = nextWord[runeLen:]
		}

		// make a valid identifier by replacing "bad" characters with underscores
		nextWord = strings.Map(func(r rune) rune {
			if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
				return r
			}
			return '_'
		}, nextWord)

		alias = nextWord + alias
		if len(restPath) > 0 {
			restPath, nextWord = path.Split(restPath[:len(restPath)-1] /* chop off final slash */)
		}
	}

	l.byPath[importPath] = alias
	l.byAlias[alias] = importPath
	return alias
}

// ImportSpecs returns a string form of each import spec
// (i.e. `alias "path/to/import").  Aliases are only present
// when they don't match the package name.
func (l *importsList) ImportSpecs() []string {
	res := make([]string, 0, len(l.byPath))
	for importPath, alias := range l.byPath {
		pkg := l.pkg.Imports()[importPath]
		if pkg != nil && pkg.Name == alias {
			// don't print if alias is the same as package name
			// (we've already taken care of duplicates).
			res = append(res, fmt.Sprintf("%q", importPath))
		} else {
			res = append(res, fmt.Sprintf("%s %q", alias, importPath))
		}
	}
	return res
}

// namingInfo holds package and syntax for referencing a field, type,
// etc.  It's used to allow lazily marking import usage.
// You should generally retrieve the syntax using Syntax.
type namingInfo struct {
	// typeInfo is the type being named.
	typeInfo     types.Type
	nameOverride string
}

// Syntax calculates the code representation of the given type or name,
// and marks that is used (potentially marking an import as used).
func (n *namingInfo) Syntax(basePkg *loader.Package, imports *importsList) string {
	if n.nameOverride != "" {
		return n.nameOverride
	}

	// NB(directxman12): typeInfo.String gets us most of the way there,
	// but fails (for us) on named imports, since it uses the full package path.
	switch typeInfo := n.typeInfo.(type) {
	case *types.Named:
		// register that we need an import for this type,
		// so we can get the appropriate alias to use.
		typeName := typeInfo.Obj()
		otherPkg := typeName.Pkg()
		if otherPkg == basePkg.Types {
			// local import
			return typeName.Name()
		}
		alias := imports.NeedImport(loader.NonVendorPath(otherPkg.Path()))
		return alias + "." + typeName.Name()
	case *types.Basic:
		return typeInfo.String()
	case *types.Pointer:
		return "*" + (&namingInfo{typeInfo: typeInfo.Elem()}).Syntax(basePkg, imports)
	case *types.Slice:
		return "[]" + (&namingInfo{typeInfo: typeInfo.Elem()}).Syntax(basePkg, imports)
	case *types.Map:
		return fmt.Sprintf(
			"map[%s]%s",
			(&namingInfo{typeInfo: typeInfo.Key()}).Syntax(basePkg, imports),
			(&namingInfo{typeInfo: typeInfo.Elem()}).Syntax(basePkg, imports))
	default:
		basePkg.AddError(fmt.Errorf("name requested for invalid type: %s", typeInfo))
		return typeInfo.String()
	}
}

// copyMethodMakers makes DeepCopy (and related) methods for Go types,
// writing them to its codeWriter.
type copyMethodMaker struct {
	pkg *loader.Package
	*importsList
	*codeWriter
}

// GenerateMethodsFor makes DeepCopy, DeepCopyInto, and DeepCopyObject methods
// for the given type, when appropriate
func (c *copyMethodMaker) GenerateMethodsFor(root *loader.Package, info *markers.TypeInfo) {
	typeInfo := root.TypesInfo.TypeOf(info.RawSpec.Name)
	if typeInfo == types.Typ[types.Invalid] {
		root.AddError(loader.ErrFromNode(fmt.Errorf("unknown type: %s", info.Name), info.RawSpec))
	}

	// figure out if we need to use a pointer receiver -- most types get a pointer receiver,
	// except those that are aliases to types that are already pass-by-reference (pointers,
	// interfaces. maps, slices).
	ptrReceiver := usePtrReceiver(typeInfo)

	hasManualDeepCopyInto := hasDeepCopyIntoMethod(root, typeInfo)
	hasManualDeepCopy, deepCopyOnPtr := hasDeepCopyMethod(root, typeInfo)

	// only generate each method if it hasn't been implemented.
	if !hasManualDeepCopyInto {
		c.Line("// DeepCopyInto is an autogenerated deepcopy function, copying the receiver, writing into out. in must be non-nil.")
		if ptrReceiver {
			c.Linef("func (in *%s) DeepCopyInto(out *%s) {", info.Name, info.Name)
		} else {
			c.Linef("func (in %s) DeepCopyInto(out *%s) {", info.Name, info.Name)
			c.Line("{in := &in") // add an extra block so that we can redefine `in` without type issues
		}

		// just wrap the existing deepcopy if present
		if hasManualDeepCopy {
			if deepCopyOnPtr {
				c.Line("clone := in.DeepCopy()")
				c.Line("*out = *clone")
			} else {
				c.Line("*out = in.DeepCopy()")
			}
		} else {
			c.genDeepCopyIntoBlock(&namingInfo{nameOverride: info.Name}, typeInfo)
		}

		if !ptrReceiver {
			c.Line("}") // close our extra "in redefinition" block
		}
		c.Line("}")
	}

	if !hasManualDeepCopy {
		// these are both straightforward, so we just template them out.
		if ptrReceiver {
			c.Linef(ptrDeepCopy, info.Name)
		} else {
			c.Linef(bareDeepCopy, info.Name)
		}

		// maybe also generate DeepCopyObject, if asked.
		if genObjectInterface(info) {
			// we always need runtime.Object for DeepCopyObject
			runtimeAlias := c.NeedImport("k8s.io/apimachinery/pkg/runtime")
			if ptrReceiver {
				c.Linef(ptrDeepCopyObj, info.Name, runtimeAlias)
			} else {
				c.Linef(bareDeepCopyObj, info.Name, runtimeAlias)
			}
		}
	}
}

// genDeepCopyBody generates a DeepCopyInto block for the given type.  The
// block is *not* wrapped in curly braces.
func (c *copyMethodMaker) genDeepCopyIntoBlock(actualName *namingInfo, typeInfo types.Type) {
	// we calculate *how* we should copy mostly based on the "eventual" type of
	// a given type (i.e. the type that results from following all aliases)
	last := eventualUnderlyingType(typeInfo)

	// we might hit a type that has a manual deepcopy method written on non-root types
	// (this case is handled for root types in GenerateMethodFor).
	// In that case (when we're not dealing with a pointer, since those need special handling
	// to match 1-to-1 with k8s deepcopy-gen), just use that.
	if _, isPtr := last.(*types.Pointer); !isPtr && hasAnyDeepCopyMethod(c.pkg, typeInfo) {
		c.Line("*out = in.DeepCopy()")
		return
	}

	switch last := last.(type) {
	case *types.Basic:
		switch last.Kind() {
		case types.Invalid, types.UnsafePointer:
			c.pkg.AddError(fmt.Errorf("invalid type: %s", last))
		default:
			// basic types themselves can be "shallow" copied, so all we need
			// to do is check if our *actual* type (not the underlying one) has
			// a custom method implemented.
			if hasMethod, _ := hasDeepCopyMethod(c.pkg, typeInfo); hasMethod {
				c.Line("*out = in.DeepCopy()")
			}
			c.Line("*out = *in")
		}
	case *types.Map:
		c.genMapDeepCopy(actualName, last)
	case *types.Slice:
		c.genSliceDeepCopy(actualName, last)
	case *types.Struct:
		c.genStructDeepCopy(actualName, last)
	case *types.Pointer:
		c.genPointerDeepCopy(actualName, last)
	case *types.Named:
		// handled via the above loop, should never happen
		c.pkg.AddError(fmt.Errorf("interface type %s encountered directly, invalid condition", last))
	default:
		c.pkg.AddError(fmt.Errorf("invalid type: %s", last))
	}
}

// genMapDeepCopy generates DeepCopy code for the given named type whose eventual
// type is the given map type.
func (c *copyMethodMaker) genMapDeepCopy(actualName *namingInfo, mapType *types.Map) {
	// maps *must* have shallow-copiable types, since we just iterate
	// through the keys, only trying to deepcopy the values.
	if !fineToShallowCopy(mapType.Key()) {
		c.pkg.AddError(fmt.Errorf("invalid map key type: %s", mapType.Key()))
		return
	}

	// make our actual type (not the underlying one)...
	c.Linef("*out = make(%[1]s, len(*in))", actualName.Syntax(c.pkg, c.importsList))

	// ...and copy each element appropriately
	c.For("key, val := range *in", func() {
		// check if we have manually written methods,
		// in which case we'll just try and use those
		hasDeepCopy, copyOnPtr := hasDeepCopyMethod(c.pkg, mapType.Elem())
		hasDeepCopyInto := hasDeepCopyIntoMethod(c.pkg, mapType.Elem())
		switch {
		case hasDeepCopyInto || hasDeepCopy:
			// use the manually-written methods
			_, fieldIsPtr := mapType.Elem().(*types.Pointer)                       // is "out" actually a pointer
			inIsPtr := resultWillBePointer(mapType.Elem(), hasDeepCopy, copyOnPtr) // does copying "in" produce a pointer
			if hasDeepCopy {
				// If we're calling DeepCopy, check if it's receiver needs a pointer
				inIsPtr = copyOnPtr
			}
			if inIsPtr == fieldIsPtr {
				c.Line("(*out)[key] = val.DeepCopy()")
			} else if fieldIsPtr {
				c.Line("{") // use a block because we use `x` as a temporary
				c.Line("x := val.DeepCopy()")
				c.Line("(*out)[key] = &x")
				c.Line("}")
			} else {
				c.Line("(*out)[key] = *val.DeepCopy()")
			}
		case fineToShallowCopy(mapType.Elem()):
			// just shallow copy types for which it's safe to do so
			c.Line("(*out)[key] = val")
		default:
			// otherwise, we've got some kind-specific actions,
			// based on the element's eventual type.

			underlyingElem := eventualUnderlyingType(mapType.Elem())

			// if it passes by reference, let the main switch handle it
			if passesByReference(underlyingElem) {
				c.Linef("var outVal %[1]s", (&namingInfo{typeInfo: underlyingElem}).Syntax(c.pkg, c.importsList))
				c.IfElse("val == nil", func() {
					c.Line("(*out)[key] = nil")
				}, func() {
					c.Line("in, out := &val, &outVal")
					c.genDeepCopyIntoBlock(&namingInfo{typeInfo: mapType.Elem()}, mapType.Elem())
				})
				c.Line("(*out)[key] = outVal")

				return
			}

			// otherwise...
			switch underlyingElem := underlyingElem.(type) {
			case *types.Struct:
				// structs will have deepcopy generated for them, so use that
				c.Line("(*out)[key] = *val.DeepCopy()")
			default:
				c.pkg.AddError(fmt.Errorf("invalid map value type: %s", underlyingElem))
				return
			}
		}
	})
}

// genSliceDeepCopy generates DeepCopy code for the given named type whose
// underlying type is the given slice.
func (c *copyMethodMaker) genSliceDeepCopy(actualName *namingInfo, sliceType *types.Slice) {
	underlyingElem := eventualUnderlyingType(sliceType.Elem())

	// make the actual type (not the underlying)
	c.Linef("*out = make(%[1]s, len(*in))", actualName.Syntax(c.pkg, c.importsList))

	// check if we need to do anything special, or just copy each element appropriately
	switch {
	case hasAnyDeepCopyMethod(c.pkg, sliceType.Elem()):
		// just use deepcopy if it's present (deepcopyinto will be filled in by our code)
		c.For("i := range *in", func() {
			c.Line("(*in)[i].DeepCopyInto(&(*out)[i])")
		})
	case fineToShallowCopy(underlyingElem):
		// shallow copy if ok
		c.Line("copy(*out, *in)")
	default:
		// copy each element appropriately
		c.For("i := range *in", func() {
			// fall back to normal code for reference types or those with custom logic
			if passesByReference(underlyingElem) || hasAnyDeepCopyMethod(c.pkg, sliceType.Elem()) {
				c.If("(*in)[i] != nil", func() {
					c.Line("in, out := &(*in)[i], &(*out)[i]")
					c.genDeepCopyIntoBlock(&namingInfo{typeInfo: sliceType.Elem()}, sliceType.Elem())
				})
				return
			}

			switch underlyingElem.(type) {
			case *types.Struct:
				// structs will always have deepcopy
				c.Linef("(*in)[i].DeepCopyInto(&(*out)[i])")
			default:
				c.pkg.AddError(fmt.Errorf("invalid slice element type: %s", underlyingElem))
			}
		})
	}
}

// genStructDeepCopy generates DeepCopy code for the given named type whose
// underlying type is the given struct.
func (c *copyMethodMaker) genStructDeepCopy(_ *namingInfo, structType *types.Struct) {
	c.Line("*out = *in")

	for i := 0; i < structType.NumFields(); i++ {
		field := structType.Field(i)

		// if we have a manual deepcopy, use that
		hasDeepCopy, copyOnPtr := hasDeepCopyMethod(c.pkg, field.Type())
		hasDeepCopyInto := hasDeepCopyIntoMethod(c.pkg, field.Type())
		if hasDeepCopyInto || hasDeepCopy {
			// NB(directxman12): yes, I know this is kind-of weird that we
			// have all this special-casing here, but it's nice for testing
			// purposes to be 1-to-1 with deepcopy-gen, which does all sorts of
			// stuff like this (I'm pretty sure I found some codepaths that
			// never execute there, because they're pretty clearly invalid
			// syntax).

			_, fieldIsPtr := field.Type().(*types.Pointer)
			inIsPtr := resultWillBePointer(field.Type(), hasDeepCopy, copyOnPtr)
			if fieldIsPtr {
				// we'll need a if block to check for nilness
				// we'll let genDeepCopyIntoBlock handle the details, we just needed the setup
				c.If(fmt.Sprintf("in.%s != nil", field.Name()), func() {
					c.Linef("in, out := &in.%[1]s, &out.%[1]s", field.Name())
					c.genDeepCopyIntoBlock(&namingInfo{typeInfo: field.Type()}, field.Type())
				})
			} else {
				// special-case for compatibility with deepcopy-gen
				if inIsPtr == fieldIsPtr {
					c.Linef("out.%[1]s = in.%[1]s.DeepCopy()", field.Name())
				} else {
					c.Linef("in.%[1]s.DeepCopyInto(&out.%[1]s)", field.Name())
				}
			}
			continue
		}

		// pass-by-reference fields get delegated to the main type
		underlyingField := eventualUnderlyingType(field.Type())
		if passesByReference(underlyingField) {
			c.If(fmt.Sprintf("in.%s != nil", field.Name()), func() {
				c.Linef("in, out := &in.%[1]s, &out.%[1]s", field.Name())
				c.genDeepCopyIntoBlock(&namingInfo{typeInfo: field.Type()}, field.Type())
			})
			continue
		}

		// otherwise...
		switch underlyingField := underlyingField.(type) {
		case *types.Basic:
			switch underlyingField.Kind() {
			case types.Invalid, types.UnsafePointer:
				c.pkg.AddError(loader.ErrFromNode(fmt.Errorf("invalid field type: %s", underlyingField), field))
				return
			default:
				// nothing to do, initial assignment copied this
			}
		case *types.Struct:
			if fineToShallowCopy(field.Type()) {
				c.Linef("out.%[1]s = in.%[1]s", field.Name())
			} else {
				c.Linef("in.%[1]s.DeepCopyInto(&out.%[1]s)", field.Name())
			}
		default:
			c.pkg.AddError(loader.ErrFromNode(fmt.Errorf("invalid field type: %s", underlyingField), field))
			return
		}
	}
}

// genPointerDeepCopy generates DeepCopy code for the given named type whose
// underlying type is the given struct.
func (c *copyMethodMaker) genPointerDeepCopy(_ *namingInfo, pointerType *types.Pointer) {
	underlyingElem := eventualUnderlyingType(pointerType.Elem())

	// if we have a manually written deepcopy, just use that
	hasDeepCopy, copyOnPtr := hasDeepCopyMethod(c.pkg, pointerType.Elem())
	hasDeepCopyInto := hasDeepCopyIntoMethod(c.pkg, pointerType.Elem())
	if hasDeepCopyInto || hasDeepCopy {
		outNeedsPtr := resultWillBePointer(pointerType.Elem(), hasDeepCopy, copyOnPtr)
		if hasDeepCopy {
			outNeedsPtr = copyOnPtr
		}
		if outNeedsPtr {
			c.Line("*out = (*in).DeepCopy()")
		} else {
			c.Line("x := (*in).DeepCopy()")
			c.Line("*out = &x")
		}
		return
	}

	// shallow-copiable types are pretty easy
	if fineToShallowCopy(underlyingElem) {
		c.Linef("*out = new(%[1]s)", (&namingInfo{typeInfo: pointerType.Elem()}).Syntax(c.pkg, c.importsList))
		c.Line("**out = **in")
		return
	}

	// pass-by-reference types get delegated to the main switch
	if passesByReference(underlyingElem) {
		c.Linef("*out = new(%s)", (&namingInfo{typeInfo: underlyingElem}).Syntax(c.pkg, c.importsList))
		c.If("**in != nil", func() {
			c.Line("in, out := *in, *out")
			c.genDeepCopyIntoBlock(&namingInfo{typeInfo: underlyingElem}, eventualUnderlyingType(underlyingElem))
		})
		return
	}

	// otherwise...
	switch underlyingElem := underlyingElem.(type) {
	case *types.Struct:
		c.Linef("*out = new(%[1]s)", (&namingInfo{typeInfo: pointerType.Elem()}).Syntax(c.pkg, c.importsList))
		c.Line("(*in).DeepCopyInto(*out)")
	default:
		c.pkg.AddError(fmt.Errorf("invalid pointer element type: %s", underlyingElem))
		return
	}
}

// usePtrReceiver checks if we need a pointer receiver on methods for the given type
// Pass-by-reference types don't get pointer receivers.
func usePtrReceiver(typeInfo types.Type) bool {
	switch typeInfo.(type) {
	case *types.Pointer:
		return false
	case *types.Map:
		return false
	case *types.Slice:
		return false
	case *types.Named:
		return usePtrReceiver(typeInfo.Underlying())
	default:
		return true
	}
}

func resultWillBePointer(typeInfo types.Type, hasDeepCopy, deepCopyOnPtr bool) bool {
	// if we have a manual deepcopy, we can just check what that returns
	if hasDeepCopy {
		return deepCopyOnPtr
	}

	// otherwise, we'll need to check its type
	switch typeInfo := typeInfo.(type) {
	case *types.Pointer:
		// NB(directxman12): we don't have to worry about the elem having a deepcopy,
		// since hasManualDeepCopy would've caught that.

		// we'll be calling on the elem, so check that
		return resultWillBePointer(typeInfo.Elem(), false, false)
	case *types.Map:
		return false
	case *types.Slice:
		return false
	case *types.Named:
		return resultWillBePointer(typeInfo.Underlying(), false, false)
	default:
		return true
	}
}

// shouldBeCopied checks if we're supposed to make deepcopy methods the given type.
//
// This is the case if it's exported *and* either:
// - has a partial manual DeepCopy implementation (in which case we fill in the rest)
// - aliases to a non-basic type eventually
// - is a struct
func shouldBeCopied(pkg *loader.Package, info *markers.TypeInfo) bool {
	if !ast.IsExported(info.Name) {
		return false
	}

	typeInfo := pkg.TypesInfo.TypeOf(info.RawSpec.Name)
	if typeInfo == types.Typ[types.Invalid] {
		pkg.AddError(loader.ErrFromNode(fmt.Errorf("unknown type: %s", info.Name), info.RawSpec))
		return false
	}

	// according to gengo, everything named is an alias, except for an alias to a pointer,
	// which is just a pointer, afaict.  Just roll with it.
	if asPtr, isPtr := typeInfo.(*types.Named).Underlying().(*types.Pointer); isPtr {
		typeInfo = asPtr
	}

	lastType := typeInfo
	if _, isNamed := typeInfo.(*types.Named); isNamed {
		// if it has a manual deepcopy or deepcopyinto, we're fine
		if hasAnyDeepCopyMethod(pkg, typeInfo) {
			return true
		}

		for underlyingType := typeInfo.Underlying(); underlyingType != lastType; lastType, underlyingType = underlyingType, underlyingType.Underlying() {
			// if it has a manual deepcopy or deepcopyinto, we're fine
			if hasAnyDeepCopyMethod(pkg, underlyingType) {
				return true
			}

			// aliases to other things besides basics need copy methods
			// (basics can be straight-up shallow-copied)
			if _, isBasic := underlyingType.(*types.Basic); !isBasic {
				return true
			}
		}
	}

	// structs are the only thing that's not a basic that's copiable by default
	_, isStruct := lastType.(*types.Struct)
	return isStruct
}

// hasDeepCopyMethod checks if this type has a manual DeepCopy method and if
// the method has a pointer receiver.
func hasDeepCopyMethod(pkg *loader.Package, typeInfo types.Type) (bool, bool) {
	deepCopyMethod, ind, _ := types.LookupFieldOrMethod(typeInfo, true /* check pointers too */, pkg.Types, "DeepCopy")
	if len(ind) != 1 {
		// ignore embedded methods
		return false, false
	}
	if deepCopyMethod == nil {
		return false, false
	}

	methodSig := deepCopyMethod.Type().(*types.Signature)
	if methodSig.Params() != nil && methodSig.Params().Len() != 0 {
		return false, false
	}
	if methodSig.Results() == nil || methodSig.Results().Len() != 1 {
		return false, false
	}

	recvAsPtr, recvIsPtr := methodSig.Recv().Type().(*types.Pointer)
	if recvIsPtr {
		// NB(directxman12): the pointer type returned here isn't comparable even though they
		// have the same underlying type, for some reason (probably that
		// LookupFieldOrMethod calls types.NewPointer for us), so check the
		// underlying values.

		resultPtr, resultIsPtr := methodSig.Results().At(0).Type().(*types.Pointer)
		if !resultIsPtr {
			// pointer vs non-pointer are different types
			return false, false
		}

		if recvAsPtr.Elem() != resultPtr.Elem() {
			return false, false
		}
	} else if methodSig.Results().At(0).Type() != methodSig.Recv().Type() {
		return false, false
	}

	return true, recvIsPtr
}

// hasDeepCopyIntoMethod checks if this type has a manual DeepCopyInto method.
func hasDeepCopyIntoMethod(pkg *loader.Package, typeInfo types.Type) bool {
	deepCopyMethod, ind, _ := types.LookupFieldOrMethod(typeInfo, true /* check pointers too */, pkg.Types, "DeepCopyInto")
	if len(ind) != 1 {
		// ignore embedded methods
		return false
	}
	if deepCopyMethod == nil {
		return false
	}

	methodSig := deepCopyMethod.Type().(*types.Signature)
	if methodSig.Params() == nil || methodSig.Params().Len() != 1 {
		return false
	}
	paramPtr, isPtr := methodSig.Params().At(0).Type().(*types.Pointer)
	if !isPtr {
		return false
	}
	if methodSig.Results() != nil && methodSig.Results().Len() != 0 {
		return false
	}

	if recvPtr, recvIsPtr := methodSig.Recv().Type().(*types.Pointer); recvIsPtr {
		// NB(directxman12): the pointer type returned here isn't comparable even though they
		// have the same underlying type, for some reason (probably that
		// LookupFieldOrMethod calls types.NewPointer for us), so check the
		// underlying values.
		return paramPtr.Elem() == recvPtr.Elem()
	}
	return methodSig.Recv().Type() == paramPtr.Elem()
}

// hasAnyDeepCopyMethod checks if the given method has DeepCopy or DeepCopyInto
// (either of which implies the other will exist eventually).
func hasAnyDeepCopyMethod(pkg *loader.Package, typeInfo types.Type) bool {
	hasDeepCopy, _ := hasDeepCopyMethod(pkg, typeInfo)
	return hasDeepCopy || hasDeepCopyIntoMethod(pkg, typeInfo)
}

// eventualUnderlyingType gets the "final" type in a sequence of named aliases.
// It's effectively a shortcut for calling Underlying in a loop.
func eventualUnderlyingType(typeInfo types.Type) types.Type {
	last := typeInfo
	for underlying := typeInfo.Underlying(); underlying != last; last, underlying = underlying, underlying.Underlying() {
		// get the actual underlying type
	}
	return last
}

// fineToShallowCopy checks if a shallow-copying a type is equivalent to deepcopy-ing it.
func fineToShallowCopy(typeInfo types.Type) bool {
	switch typeInfo := typeInfo.(type) {
	case *types.Basic:
		// basic types (int, string, etc) are always fine to shallow-copy,
		// except for Invalid and UnsafePointer, which can't be copied at all.
		switch typeInfo.Kind() {
		case types.Invalid, types.UnsafePointer:
			return false
		default:
			return true
		}
	case *types.Named:
		// aliases are fine to shallow-copy as long as they resolve to a shallow-copyable type
		return fineToShallowCopy(typeInfo.Underlying())
	case *types.Struct:
		// structs are fine to shallow-copy if they have all shallow-copyable fields
		for i := 0; i < typeInfo.NumFields(); i++ {
			field := typeInfo.Field(i)
			if !fineToShallowCopy(field.Type()) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// passesByReference checks if the given type passesByReference
// (except for interfaces, which are handled separately).
func passesByReference(typeInfo types.Type) bool {
	switch typeInfo.(type) {
	case *types.Slice:
		return true
	case *types.Map:
		return true
	case *types.Pointer:
		return true
	default:
		return false
	}
}

var (
	// ptrDeepCopy is a DeepCopy for a type with an existing DeepCopyInto and a pointer receiver.
	ptrDeepCopy = `
// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new %[1]s.
func (in *%[1]s) DeepCopy() *%[1]s {
	if in == nil { return nil }
	out := new(%[1]s)
	in.DeepCopyInto(out)
	return out
}
`

	// ptrDeepCopy is a DeepCopy for a type with an existing DeepCopyInto and a non-pointer receiver.
	bareDeepCopy = `
// DeepCopy is an autogenerated deepcopy function, copying the receiver, creating a new %[1]s.
func (in %[1]s) DeepCopy() %[1]s {
	if in == nil { return nil }
	out := new(%[1]s)
	in.DeepCopyInto(out)
	return *out
}
`

	// ptrDeepCopy is a DeepCopyObject for a type with an existing DeepCopyInto and a pointer receiver.
	ptrDeepCopyObj = `
// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in *%[1]s) DeepCopyObject() %[2]s.Object {
	if c := in.DeepCopy(); c != nil {
		return c
	}
	return nil
}
`
	// ptrDeepCopy is a DeepCopyObject for a type with an existing DeepCopyInto and a non-pointer receiver.
	bareDeepCopyObj = `
// DeepCopyObject is an autogenerated deepcopy function, copying the receiver, creating a new runtime.Object.
func (in %[1]s) DeepCopyObject() %[2]s.Object {
	return in.DeepCopy()
}
`
)
