package pgs

import (
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
	plugin_go "github.com/golang/protobuf/protoc-gen-go/plugin"
)

// AST encapsulates the entirety of the input CodeGeneratorRequest from protoc,
// parsed to build the Entity graph used by PG*.
type AST interface {
	// Targets returns a map of the files specified in the protoc execution. For
	// all Entities contained in these files, BuildTarget will return true.
	Targets() map[string]File

	// Packages returns all the imported packages (including those for the target
	// Files). This is limited to just the files that were imported by target
	// protos, either directly or transitively.
	Packages() map[string]Package

	// Lookup allows getting an Entity from the graph by its fully-qualified name
	// (FQN). The FQN uses dot notation of the form ".{package}.{entity}", or the
	// input path for Files.
	Lookup(name string) (Entity, bool)
}

type graph struct {
	d Debugger

	targets    map[string]File
	packages   map[string]Package
	entities   map[string]Entity
	extensions []Extension
}

func (g *graph) Targets() map[string]File { return g.targets }

func (g *graph) Packages() map[string]Package { return g.packages }

func (g *graph) Lookup(name string) (Entity, bool) {
	e, ok := g.entities[name]
	return e, ok
}

// ProcessDescriptors is deprecated; use ProcessCodeGeneratorRequest instead
func ProcessDescriptors(debug Debugger, req *plugin_go.CodeGeneratorRequest) AST {
	return ProcessCodeGeneratorRequest(debug, req)
}

// ProcessCodeGeneratorRequest converts a CodeGeneratorRequest from protoc into a fully
// connected AST entity graph. An error is returned if the input is malformed.
func ProcessCodeGeneratorRequest(debug Debugger, req *plugin_go.CodeGeneratorRequest) AST {
	g := &graph{
		d:          debug,
		targets:    make(map[string]File, len(req.GetFileToGenerate())),
		packages:   make(map[string]Package),
		entities:   make(map[string]Entity),
		extensions: []Extension{},
	}

	for _, f := range req.GetFileToGenerate() {
		g.targets[f] = nil
	}

	for _, f := range req.GetProtoFile() {
		pkg := g.hydratePackage(f)
		pkg.addFile(g.hydrateFile(pkg, f))
	}

	for _, e := range g.extensions {
		e.addType(g.hydrateFieldType(e))
		extendee := g.mustSeen(e.Descriptor().GetExtendee()).(Message)
		e.setExtendee(extendee)
		if extendee != nil {
			extendee.addExtension(e)
		}
	}

	return g
}

// ProcessCodeGeneratorRequestBidirectional has the same functionality as
// ProcessCodeGeneratorRequest, but builds the AST so that files, messages,
// and enums have references to any files or messages that directly or
// transitively depend on them.
func ProcessCodeGeneratorRequestBidirectional(debug Debugger, req *plugin_go.CodeGeneratorRequest) AST {
	g := ProcessCodeGeneratorRequest(debug, req)
	for _, pkg := range g.Packages() {
		for _, f := range pkg.Files() {
			for _, m := range f.AllMessages() {
				for _, field := range m.Fields() {
					assignDependent(field.Type(), m)
				}
			}
		}
	}
	return g
}

// ProcessFileDescriptorSet converts a FileDescriptorSet from protoc into a
// fully connected AST entity graph. An error is returned if the input is
// malformed or missing dependencies. To generate a self-contained
// FileDescriptorSet, run the following command:
//
//   protoc -o path/to/fdset.bin --include_imports $PROTO_FILES
//
// The emitted AST will have no values in the Targets map, but Packages will be
// populated. If used for testing purposes, the Targets map can be manually
// populated.
func ProcessFileDescriptorSet(debug Debugger, fdset *descriptor.FileDescriptorSet) AST {
	req := plugin_go.CodeGeneratorRequest{ProtoFile: fdset.File}
	return ProcessCodeGeneratorRequest(debug, &req)
}

// ProcessFileDescriptorSetBidirectional has the same functionality as
// ProcessFileDescriptorSet, but builds the AST so that files, messages,
// and enums have references to any files or messages that directly or
// transitively depend on them.
func ProcessFileDescriptorSetBidirectional(debug Debugger, fdset *descriptor.FileDescriptorSet) AST {
	req := plugin_go.CodeGeneratorRequest{ProtoFile: fdset.File}
	return ProcessCodeGeneratorRequestBidirectional(debug, &req)
}

func (g *graph) hydratePackage(f *descriptor.FileDescriptorProto) Package {
	lookup := f.GetPackage()
	if pkg, exists := g.packages[lookup]; exists {
		return pkg
	}

	p := &pkg{fd: f}
	g.packages[lookup] = p

	return p
}

func (g *graph) hydrateFile(pkg Package, f *descriptor.FileDescriptorProto) File {
	fl := &file{
		pkg:  pkg,
		desc: f,
	}
	if pkg := f.GetPackage(); pkg != "" {
		fl.fqn = "." + pkg
	} else {
		fl.fqn = ""
	}
	g.add(fl)

	for _, dep := range f.GetDependency() {
		// the AST is built in topological order so a file's dependencies are always hydrated first
		d := g.mustSeen(dep).(File)
		fl.addFileDependency(d)
		d.addDependent(fl)
	}

	if _, fl.buildTarget = g.targets[f.GetName()]; fl.buildTarget {
		g.targets[f.GetName()] = fl
	}

	enums := f.GetEnumType()
	fl.enums = make([]Enum, 0, len(enums))
	for _, e := range enums {
		fl.addEnum(g.hydrateEnum(fl, e))
	}

	exts := f.GetExtension()
	fl.defExts = make([]Extension, 0, len(exts))
	for _, ext := range exts {
		e := g.hydrateExtension(fl, ext)
		fl.addDefExtension(e)
	}

	msgs := f.GetMessageType()
	fl.msgs = make([]Message, 0, len(f.GetMessageType()))
	for _, msg := range msgs {
		fl.addMessage(g.hydrateMessage(fl, msg))
	}

	srvs := f.GetService()
	fl.srvs = make([]Service, 0, len(srvs))
	for _, sd := range srvs {
		fl.addService(g.hydrateService(fl, sd))
	}

	for _, m := range fl.AllMessages() {
		for _, me := range m.MapEntries() {
			for _, fld := range me.Fields() {
				fld.addType(g.hydrateFieldType(fld))
			}
		}

		for _, fld := range m.Fields() {
			fld.addType(g.hydrateFieldType(fld))
		}
	}

	g.hydrateSourceCodeInfo(fl, f)

	return fl
}

func (g *graph) hydrateSourceCodeInfo(f File, fd *descriptor.FileDescriptorProto) {
	for _, loc := range fd.GetSourceCodeInfo().GetLocation() {
		info := sci{desc: loc}
		path := loc.GetPath()

		if len(path) == 1 {
			switch path[0] {
			case syntaxPath:
				f.addSourceCodeInfo(info)
			case packagePath:
				f.addPackageSourceCodeInfo(info)
			default:
				continue
			}
		}

		if e := f.childAtPath(path); e != nil {
			e.addSourceCodeInfo(info)
		}
	}
}

func (g *graph) hydrateEnum(p ParentEntity, ed *descriptor.EnumDescriptorProto) Enum {
	e := &enum{
		desc:   ed,
		parent: p,
	}
	e.fqn = fullyQualifiedName(p, e)
	g.add(e)

	vals := ed.GetValue()
	e.vals = make([]EnumValue, 0, len(vals))
	for _, vd := range vals {
		e.addValue(g.hydrateEnumValue(e, vd))
	}

	return e
}

func (g *graph) hydrateEnumValue(e Enum, vd *descriptor.EnumValueDescriptorProto) EnumValue {
	ev := &enumVal{
		desc: vd,
		enum: e,
	}
	ev.fqn = fullyQualifiedName(e, ev)
	g.add(ev)

	return ev
}

func (g *graph) hydrateService(f File, sd *descriptor.ServiceDescriptorProto) Service {
	s := &service{
		desc: sd,
		file: f,
	}
	s.fqn = fullyQualifiedName(f, s)
	g.add(s)

	for _, md := range sd.GetMethod() {
		s.addMethod(g.hydrateMethod(s, md))
	}

	return s
}

func (g *graph) hydrateMethod(s Service, md *descriptor.MethodDescriptorProto) Method {
	m := &method{
		desc:    md,
		service: s,
	}
	m.fqn = fullyQualifiedName(s, m)
	g.add(m)

	m.in = g.mustSeen(md.GetInputType()).(Message)
	m.out = g.mustSeen(md.GetOutputType()).(Message)

	return m
}

func (g *graph) hydrateMessage(p ParentEntity, md *descriptor.DescriptorProto) Message {
	m := &msg{
		desc:   md,
		parent: p,
	}
	m.fqn = fullyQualifiedName(p, m)
	g.add(m)

	for _, ed := range md.GetEnumType() {
		m.addEnum(g.hydrateEnum(m, ed))
	}

	m.preservedMsgs = make([]Message, len(md.GetNestedType()))
	for i, nmd := range md.GetNestedType() {
		nm := g.hydrateMessage(m, nmd)
		if nm.IsMapEntry() {
			m.addMapEntry(nm)
		} else {
			m.addMessage(nm)
		}
		m.preservedMsgs[i] = nm
	}

	for _, od := range md.GetOneofDecl() {
		m.addOneOf(g.hydrateOneOf(m, od))
	}

	for _, fd := range md.GetField() {
		fld := g.hydrateField(m, fd)
		m.addField(fld)

		if idx := fld.Descriptor().OneofIndex; idx != nil {
			m.oneofs[*idx].addField(fld)
		}
	}

	exts := md.GetExtension()
	m.defExts = make([]Extension, 0, len(exts))
	for _, ext := range md.GetExtension() {
		e := g.hydrateExtension(m, ext)
		m.addDefExtension(e)
	}

	return m
}

func (g *graph) hydrateField(m Message, fd *descriptor.FieldDescriptorProto) Field {
	f := &field{
		desc: fd,
		msg:  m,
	}
	f.fqn = fullyQualifiedName(f.msg, f)
	g.add(f)

	return f
}

func (g *graph) hydrateOneOf(m Message, od *descriptor.OneofDescriptorProto) OneOf {
	o := &oneof{
		desc: od,
		msg:  m,
	}
	o.fqn = fullyQualifiedName(m, o)
	g.add(o)

	return o
}

func (g *graph) hydrateExtension(parent ParentEntity, fd *descriptor.FieldDescriptorProto) Extension {
	ext := &ext{
		parent: parent,
	}
	ext.desc = fd
	ext.fqn = fullyQualifiedName(parent, ext)
	g.add(ext)
	g.extensions = append(g.extensions, ext)

	return ext
}

func (g *graph) hydrateFieldType(fld Field) FieldType {
	s := &scalarT{fld: fld}

	switch {
	case s.ProtoType() == GroupT:
		g.d.Fail("group types are deprecated and unsupported. Use an embedded message instead.")
		return nil
	case s.ProtoLabel() == Repeated:
		return g.hydrateRepeatedFieldType(s)
	case s.ProtoType() == EnumT:
		return g.hydrateEnumFieldType(s)
	case s.ProtoType() == MessageT:
		return g.hydrateEmbedFieldType(s)
	default:
		return s
	}
}

func (g *graph) hydrateEnumFieldType(s *scalarT) FieldType {
	return &enumT{
		scalarT: s,
		enum:    g.mustSeen(s.fld.Descriptor().GetTypeName()).(Enum),
	}
}

func (g *graph) hydrateEmbedFieldType(s *scalarT) FieldType {
	return &embedT{
		scalarT: s,
		msg:     g.mustSeen(s.fld.Descriptor().GetTypeName()).(Message),
	}
}

func (g *graph) hydrateRepeatedFieldType(s *scalarT) FieldType {
	r := &repT{
		scalarT: s,
	}
	r.el = &scalarE{
		typ:   r,
		ptype: r.ProtoType(),
	}

	switch s.ProtoType() {
	case EnumT:
		r.el = &enumE{
			scalarE: r.el.(*scalarE),
			enum:    g.mustSeen(s.fld.Descriptor().GetTypeName()).(Enum),
		}
	case MessageT:
		m := g.mustSeen(s.fld.Descriptor().GetTypeName()).(Message)
		if m.IsMapEntry() {
			return g.hydrateMapFieldType(r, m)
		}

		r.el = &embedE{
			scalarE: r.el.(*scalarE),
			msg:     m,
		}
	}

	return r
}

func (g *graph) hydrateMapFieldType(r *repT, m Message) FieldType {
	mt := &mapT{repT: r}

	mt.key = m.Fields()[0].Type().toElem()
	mt.key.setType(mt)

	mt.el = m.Fields()[1].Type().toElem()
	mt.el.setType(mt)

	return mt
}

func (g *graph) mustSeen(fqn string) Entity {
	if existing, seen := g.entities[fqn]; seen {
		return existing
	}

	g.d.Failf("expected entity %q has not been hydrated", fqn)
	return nil
}

func (g *graph) add(e Entity) {
	g.entities[g.resolveFQN(e)] = e
}

func (g *graph) resolveFQN(e Entity) string {
	if f, ok := e.(File); ok {
		return f.Name().String()
	}

	return e.FullyQualifiedName()
}

func assignDependent(ft FieldType, parent Message) {
	if ft.IsEnum() {
		ft.Enum().addDependent(parent)
	} else if ft.IsEmbed() {
		ft.Embed().addDependent(parent)
	} else if ft.IsRepeated() || ft.IsMap() {
		if ft.Element().IsEnum() {
			ft.Element().Enum().addDependent(parent)
		} else if ft.Element().IsEmbed() {
			ft.Element().Embed().addDependent(parent)
		}

		if ft.IsMap() {
			if ft.Key().IsEnum() {
				ft.Key().Enum().addDependent(parent)
			} else if ft.Key().IsEmbed() {
				ft.Key().Embed().addDependent(parent)
			}
		}
	}
}

var _ AST = (*graph)(nil)
