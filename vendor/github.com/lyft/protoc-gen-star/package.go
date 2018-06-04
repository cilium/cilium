package pgs

// Package is a container that encapsulates all the files under a single
// package namespace. Specifically, this would be all the proto files loaded
// within the same directory (not recursively). While a proto file's package
// technically can differ from its sibling files, PGS will throw an error as
// this is typically a mistake or bad practice.
type Package interface {
	Node
	Commenter

	// The name of the proto package. This may or may not be the same as the Go
	// package name.
	ProtoName() Name

	// The name of the Go package. This is guaranteed to be unique.
	GoName() Name

	// The fully qualified import path for this Go Package
	ImportPath() string

	// All the files loaded for this Package
	Files() []File

	addFile(f File)

	setComments(c string)
}

type pkg struct {
	fd         packageFD
	importPath string
	name       string
	files      []File

	comments string
}

func (p *pkg) ProtoName() Name    { return Name(p.fd.GetPackage()) }
func (p *pkg) GoName() Name       { return Name(p.name) }
func (p *pkg) ImportPath() string { return p.importPath }
func (p *pkg) Comments() string   { return p.comments }

func (p *pkg) Files() []File {
	fs := make([]File, len(p.files))
	copy(fs, p.files)
	return fs
}

func (p *pkg) accept(v Visitor) (err error) {
	if v == nil {
		return nil
	}

	if v, err = v.VisitPackage(p); err != nil || v == nil {
		return
	}

	for _, f := range p.Files() {
		if err = f.accept(v); err != nil {
			return
		}
	}

	return
}

func (p *pkg) addFile(f File) {
	f.setPackage(p)
	p.files = append(p.files, f)
}

func (p *pkg) setComments(comments string) {
	p.comments = comments
}

// packageFD stands in for a *generator.FileDescriptor. The FileDescriptor
// cannot be used directly as its PackageName method calls out to a global map.
type packageFD interface {
	GetPackage() string
}

var _ Package = (*pkg)(nil)
