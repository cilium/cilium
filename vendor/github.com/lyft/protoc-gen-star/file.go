package pgs

import (
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/protoc-gen-go/generator"
)

// File describes the contents of a single proto file.
type File interface {
	ParentEntity

	// InputPath returns the input FilePath of the generated Go code. This is
	// equivalent to the value returned by Name.
	InputPath() FilePath

	// OutputPath returns the output filepath of the generated Go code
	OutputPath() FilePath

	// Descriptor returns the underlying descriptor for the proto file
	Descriptor() *generator.FileDescriptor

	// Services returns the top-level services from this proto file.
	Services() []Service

	setPackage(p Package)

	addService(s Service)

	lookupComments(name string) string
}

type file struct {
	desc        *generator.FileDescriptor
	pkg         Package
	outputPath  FilePath
	enums       []Enum
	msgs        []Message
	srvs        []Service
	buildTarget bool
	comments    map[string]string
}

func (f *file) Name() Name                            { return Name(f.desc.GetName()) }
func (f *file) FullyQualifiedName() string            { return "." + f.desc.GetPackage() }
func (f *file) Syntax() Syntax                        { return Syntax(f.desc.GetSyntax()) }
func (f *file) Package() Package                      { return f.pkg }
func (f *file) File() File                            { return f }
func (f *file) BuildTarget() bool                     { return f.buildTarget }
func (f *file) Comments() string                      { return "" }
func (f *file) Descriptor() *generator.FileDescriptor { return f.desc }
func (f *file) InputPath() FilePath                   { return FilePath(f.Name().String()) }
func (f *file) OutputPath() FilePath                  { return f.outputPath }
func (f *file) MapEntries() (me []Message)            { return nil }

func (f *file) Enums() []Enum {
	es := make([]Enum, len(f.enums))
	copy(es, f.enums)
	return es
}

func (f *file) AllEnums() []Enum {
	es := f.Enums()
	for _, m := range f.msgs {
		es = append(es, m.AllEnums()...)
	}
	return es
}

func (f *file) Messages() []Message {
	msgs := make([]Message, len(f.msgs))
	copy(msgs, f.msgs)
	return msgs
}

func (f *file) AllMessages() []Message {
	msgs := f.Messages()
	for _, m := range f.msgs {
		msgs = append(msgs, m.AllMessages()...)
	}
	return msgs
}

func (f *file) Services() []Service {
	s := make([]Service, len(f.srvs))
	copy(s, f.srvs)
	return s
}

func (f *file) Imports() (i []Package) {
	for _, m := range f.AllMessages() {
		i = append(i, m.Imports()...)
	}
	for _, s := range f.srvs {
		i = append(i, s.Imports()...)
	}
	return
}

func (f *file) Extension(desc *proto.ExtensionDesc, ext interface{}) (bool, error) {
	return extension(f.desc.GetOptions(), desc, &ext)
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

	return
}

func (f *file) setPackage(pkg Package) { f.pkg = pkg }

func (f *file) addEnum(e Enum) {
	e.setParent(f)
	f.enums = append(f.enums, e)
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

func (f *file) lookupComments(name string) string { return f.comments[name] }
