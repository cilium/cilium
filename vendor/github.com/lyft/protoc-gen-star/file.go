package pgs

import (
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
)

// File describes the contents of a single proto file.
type File interface {
	ParentEntity

	// InputPath returns the input FilePath. This is equivalent to the value
	// returned by Name.
	InputPath() FilePath

	// Descriptor returns the underlying descriptor for the proto file
	Descriptor() *descriptor.FileDescriptorProto

	// TransitiveImports returns all direct and transitive dependencies of this
	// File. Use Imports to obtain only direct dependencies.
	TransitiveImports() []File

	// Dependents returns all files where the given file was directly or
	// transitively imported.
	Dependents() []File

	// Services returns the services from this proto file.
	Services() []Service

	// SyntaxSourceCodeInfo returns the comment info attached to the `syntax`
	// stanza of the file. This method is an alias of the SourceCodeInfo method.
	SyntaxSourceCodeInfo() SourceCodeInfo

	// PackageSourceCodeInfo returns the comment info attached to the `package`
	// stanza of the file.
	PackageSourceCodeInfo() SourceCodeInfo

	setPackage(p Package)

	addFileDependency(fl File)

	addDependent(fl File)

	addService(s Service)

	addPackageSourceCodeInfo(info SourceCodeInfo)
}

type file struct {
	desc                    *descriptor.FileDescriptorProto
	fqn                     string
	pkg                     Package
	enums                   []Enum
	defExts                 []Extension
	dependents              []File
	dependentsCache         []File
	fileDependencies        []File
	msgs                    []Message
	srvs                    []Service
	buildTarget             bool
	syntaxInfo, packageInfo SourceCodeInfo
}

func (f *file) Name() Name                                  { return Name(f.desc.GetName()) }
func (f *file) FullyQualifiedName() string                  { return f.fqn }
func (f *file) Syntax() Syntax                              { return Syntax(f.desc.GetSyntax()) }
func (f *file) Package() Package                            { return f.pkg }
func (f *file) File() File                                  { return f }
func (f *file) BuildTarget() bool                           { return f.buildTarget }
func (f *file) Descriptor() *descriptor.FileDescriptorProto { return f.desc }
func (f *file) InputPath() FilePath                         { return FilePath(f.Name().String()) }
func (f *file) MapEntries() (me []Message)                  { return nil }
func (f *file) SourceCodeInfo() SourceCodeInfo              { return f.SyntaxSourceCodeInfo() }
func (f *file) SyntaxSourceCodeInfo() SourceCodeInfo        { return f.syntaxInfo }
func (f *file) PackageSourceCodeInfo() SourceCodeInfo       { return f.packageInfo }

func (f *file) Enums() []Enum {
	return f.enums
}

func (f *file) AllEnums() []Enum {
	es := f.Enums()
	for _, m := range f.msgs {
		es = append(es, m.AllEnums()...)
	}
	return es
}

func (f *file) Messages() []Message {
	return f.msgs
}

func (f *file) AllMessages() []Message {
	msgs := f.Messages()
	for _, m := range f.msgs {
		msgs = append(msgs, m.AllMessages()...)
	}
	return msgs
}

func (f *file) Services() []Service {
	return f.srvs
}

func (f *file) Imports() []File {
	out := make([]File, len(f.fileDependencies))
	copy(out, f.fileDependencies)
	return out
}

func (f *file) TransitiveImports() []File {
	importMap := make(map[string]File, len(f.fileDependencies))
	for _, fl := range f.fileDependencies {
		importMap[fl.Name().String()] = fl
		for _, imp := range fl.TransitiveImports() {
			importMap[imp.File().Name().String()] = imp
		}
	}

	out := make([]File, 0, len(importMap))
	for _, imp := range importMap {
		out = append(out, imp)
	}

	return out
}

func (f *file) Dependents() []File {
	if f.dependentsCache == nil {
		set := make(map[string]File)
		for _, fl := range f.dependents {
			set[fl.Name().String()] = fl
			for _, d := range fl.Dependents() {
				set[d.Name().String()] = d
			}
		}

		f.dependentsCache = make([]File, 0, len(set))
		for _, d := range set {
			f.dependentsCache = append(f.dependentsCache, d)
		}
	}
	return f.dependentsCache
}

func (f *file) Extension(desc *proto.ExtensionDesc, ext interface{}) (bool, error) {
	return extension(f.desc.GetOptions(), desc, &ext)
}

func (f *file) DefinedExtensions() []Extension {
	return f.defExts
}

func (f *file) accept(v Visitor) (err error) {
	if v == nil {
		return nil
	}

	if v, err = v.VisitFile(f); err != nil || v == nil {
		return
	}

	for _, e := range f.enums {
		if err = e.accept(v); err != nil {
			return
		}
	}

	for _, m := range f.msgs {
		if err = m.accept(v); err != nil {
			return
		}
	}

	for _, s := range f.srvs {
		if err = s.accept(v); err != nil {
			return
		}
	}

	for _, ext := range f.defExts {
		if err = ext.accept(v); err != nil {
			return
		}
	}

	return
}

func (f *file) addDefExtension(ext Extension) {
	f.defExts = append(f.defExts, ext)
}

func (f *file) setPackage(pkg Package) { f.pkg = pkg }

func (f *file) addEnum(e Enum) {
	e.setParent(f)
	f.enums = append(f.enums, e)
}

func (f *file) addFileDependency(fl File) {
	f.fileDependencies = append(f.fileDependencies, fl)
}

func (f *file) addDependent(fl File) {
	f.dependents = append(f.dependents, fl)
}

func (f *file) addMessage(m Message) {
	m.setParent(f)
	f.msgs = append(f.msgs, m)
}

func (f *file) addService(s Service) {
	s.setFile(f)
	f.srvs = append(f.srvs, s)
}

func (f *file) addMapEntry(m Message) { panic("cannot add map entry directly to file") }

func (f *file) childAtPath(path []int32) Entity {
	switch {
	case len(path) == 0:
		return f
	case len(path)%2 == 1: // all declaration paths are multiples of two
		return nil
	}

	var child Entity
	switch path[0] {
	case messageTypePath:
		child = f.msgs[path[1]]
	case enumTypePath:
		child = f.enums[path[1]]
	case servicePath:
		child = f.srvs[path[1]]
	default:
		return nil
	}

	return child.childAtPath(path[2:])
}

func (f *file) addSourceCodeInfo(info SourceCodeInfo) {
	f.syntaxInfo = info
}

func (f *file) addPackageSourceCodeInfo(info SourceCodeInfo) {
	f.packageInfo = info
}

var _ File = (*file)(nil)
