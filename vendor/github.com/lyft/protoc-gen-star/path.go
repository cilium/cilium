package pgs

import (
	"path"
	"strings"

	"github.com/golang/protobuf/protoc-gen-go/generator"
)

func goPackageOption(f *generator.FileDescriptor) (impPath, pkg string, ok bool) {
	pkg = f.GetOptions().GetGoPackage()
	if pkg == "" {
		return
	}
	ok = true

	slash := strings.LastIndex(pkg, "/")
	if slash < 0 {
		return
	}

	impPath, pkg = pkg, pkg[slash+1:]
	sc := strings.IndexByte(impPath, ';')
	if sc < 0 {
		return
	}

	impPath, pkg = impPath[:sc], impPath[sc+1:]
	return
}

func goFileName(f *generator.FileDescriptor, pathType PathType) string {
	name := f.GetName()
	if ext := path.Ext(name); ext == ".proto" || ext == ".protodevel" {
		name = name[:len(name)-len(ext)]
	}
	name += ".pb.go"

	if pathType == SourceRelative {
		return name
	}

	if impPath, _, ok := goPackageOption(f); ok && impPath != "" {
		_, name = path.Split(name)
		name = path.Join(impPath, name)
	}

	return name
}

func goImportPath(g *generator.Generator, f *generator.FileDescriptor) generator.GoImportPath {
	fn := goFileName(f, Parameters(g.Param).Paths())

	importPath := path.Dir(fn)
	if sub, ok := g.ImportMap[f.GetName()]; ok {
		importPath = sub
	}
	importPath = path.Join(g.ImportPrefix, importPath)

	return generator.GoImportPath(importPath)
}
