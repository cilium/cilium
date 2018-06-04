package pgs

import (
	"errors"
	"fmt"
	"strings"

	"github.com/golang/protobuf/protoc-gen-go/descriptor"
	"github.com/golang/protobuf/protoc-gen-go/generator"
)

const gathererPluginName = "gatherer"

type gatherer struct {
	*PluginBase
	entities map[string]Entity
	pkgs     map[string]Package
	targets  map[string]Package
}

func newGatherer() *gatherer { return &gatherer{PluginBase: &PluginBase{}} }

func (g *gatherer) Name() string { return gathererPluginName }

func (g *gatherer) Init(gen *generator.Generator) {
	g.PluginBase.Init(gen)
	g.targets = make(map[string]Package)
	g.pkgs = make(map[string]Package)
	g.entities = make(map[string]Entity)
}

func (g *gatherer) Generate(f *generator.FileDescriptor) {
	comments := make(map[string]string)
	for _, loc := range f.GetSourceCodeInfo().GetLocation() {
		if loc.LeadingComments == nil {
			continue
		}

		name, err := g.nameByPath(f.FileDescriptorProto, loc.Path)
		if err != nil {
			g.Debug("unable to convert path to name:", err.Error())
		}

		comments[name] = strings.TrimSuffix(loc.GetLeadingComments(), "\n")
	}

	pkg := g.hydratePackage(f, comments)
	pkg.addFile(g.hydrateFile(pkg, f, comments))
}

func (g *gatherer) hydratePackage(f *generator.FileDescriptor, comments map[string]string) Package {
	// TODO(btc): perhaps return error with specific info about failure
	importPath := goImportPath(g.Generator.Unwrap(), f)
	name := string(g.Generator.GoPackageName(importPath))
	if p, n, found := goPackageOption(f); found {
		if p != "" {
			importPath = generator.GoImportPath(p)
		}
		if n != "" {
			name = n
		}
	}

	g.push("package:" + name)
	defer g.pop()

	// have we already hydrated this package. In case we already did, and if
	// current file contains comments in the package statement, concatenate it
	// so that we don't give any precedence to whatsoever file.
	pcomments := comments[fmt.Sprintf(".%s", name)]
	if p, ok := g.pkgs[name]; ok {
		c := make([]string, 0, 2)

		ccomments := p.Comments()
		if ccomments != "" {
			c = append(c, ccomments)
		}

		if pcomments != "" {
			c = append(c, pcomments)
		}

		p.setComments(strings.Join(c, "\n"))
		return p
	}

	p := &pkg{
		fd:         f,
		name:       name,
		importPath: string(importPath),
		comments:   pcomments,
	}

	g.pkgs[name] = p
	return p
}

func (g *gatherer) hydrateFile(pkg Package, f *generator.FileDescriptor, comments map[string]string) File {
	fl := &file{
		pkg:        pkg,
		desc:       f,
		outputPath: FilePath(goFileName(f, g.Parameters().Paths())),
	}

	if out, ok := g.seen(fl); ok {
		return out.(*file)
	}
	g.add(fl)

	g.push("file:" + fl.Name().String())
	defer g.pop()

	g.Assert(f.GetPackage() == pkg.ProtoName().String(),
		"proto package names should not be mixed in the same directory (",
		pkg.ProtoName().String(), ", ", f.GetPackage(), ")")

	fl.buildTarget = g.BuildTarget(f.GetName())
	fl.comments = comments

	if _, seen := g.targets[fl.pkg.GoName().String()]; fl.buildTarget && !seen {
		g.Debug("adding target package:", fl.pkg.GoName())
		g.targets[fl.pkg.GoName().String()] = fl.pkg
	}

	fl.msgs = make([]Message, 0, len(f.GetMessageType()))
	fl.enums = make([]Enum, 0, len(f.GetEnumType()))
	fl.srvs = make([]Service, 0, len(f.GetService()))

	// populate all enum types
	for _, ed := range f.GetEnumType() {
		fl.addEnum(g.hydrateEnum(fl, ed))
	}

	// populate all message types
	for _, md := range f.GetMessageType() {
		fl.addMessage(g.hydrateMessage(fl, md))
	}

	// populates all field types. This must come after all messages to permit
	// hydrating all types prior to hydration
	for _, m := range fl.AllMessages() {
		// This must come after all messages but before normal message fields to
		// permit the later hydration.
		for _, me := range m.MapEntries() {
			for _, fld := range me.Fields() {
				fld.addType(g.hydrateFieldType(fld))
			}
		}

		for _, fld := range m.Fields() {
			fld.addType(g.hydrateFieldType(fld))
		}
	}

	// populate all services
	for _, sd := range f.GetService() {
		fl.addService(g.hydrateService(fl, sd))
	}

	return fl
}

func (g *gatherer) hydrateMessage(parent ParentEntity, md *descriptor.DescriptorProto) Message {
	m := &msg{
		rawDesc: md,
		parent:  parent,
	}

	if out, ok := g.seen(m); ok {
		return out.(*msg)
	}
	g.add(m)

	g.push("msg:" + m.Name().String())
	defer g.pop()

	name := m.FullyQualifiedName()
	m.genDesc = g.Generator.ObjectNamed(name).(*generator.Descriptor)
	m.comments = m.File().lookupComments(name)

	// populate all nested enums
	for _, ed := range md.GetEnumType() {
		m.addEnum(g.hydrateEnum(m, ed))
	}

	// populate all nested messages. If the message is a map entry type, stash it.
	for _, smd := range md.GetNestedType() {
		if sm := g.hydrateMessage(m, smd); sm.IsMapEntry() {
			m.addMapEntry(sm)
		} else {
			m.addMessage(sm)
		}
	}

	// populate all fields
	for _, fd := range md.GetField() {
		m.addField(g.hydrateField(m, fd))
	}

	// populate all oneofs. This must come after the fields to properly associate
	// the field relationships
	for i, od := range md.GetOneofDecl() {
		m.addOneOf(g.hydrateOneOf(m, int32(i), od))
	}

	return m
}

func (g *gatherer) hydrateField(msg Message, fd *descriptor.FieldDescriptorProto) Field {
	f := &field{
		desc: fd,
		msg:  msg,
	}

	if out, ok := g.seen(f); ok {
		return out.(*field)
	}
	g.add(f)

	f.comments = f.File().lookupComments(f.FullyQualifiedName())

	return f
}

func (g *gatherer) hydrateFieldType(fld Field) FieldType {
	g.push("field-type:" + fld.FullyQualifiedName())
	defer g.pop()

	msg := fld.Message().Descriptor()
	name, _ := g.Generator.GoType(msg, fld.Descriptor())

	s := &scalarT{
		fld:  fld,
		name: TypeName(name),
	}

	switch {
	case s.ProtoType() == GroupT:
		g.Fail("group types are deprecated and unsupported. Use an embedded message instead.")
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

func (g *gatherer) hydrateEnumFieldType(s *scalarT) FieldType {
	e := &enumT{scalarT: s}

	ent, ok := g.seenObj(g.Generator.ObjectNamed(s.fld.Descriptor().GetTypeName()))
	g.Assert(ok, "enum type not seen")

	en, ok := ent.(Enum)
	g.Assert(ok, "unexpected entity type")
	e.enum = en

	return e
}

func (g *gatherer) hydrateEmbedFieldType(s *scalarT) FieldType {
	e := &embedT{scalarT: s}

	ent, ok := g.seenObj(g.Generator.ObjectNamed(s.fld.Descriptor().GetTypeName()))
	g.Assert(ok, "embed type not seen")

	m, ok := ent.(Message)
	g.Assert(ok, "unexpected entity type")
	e.msg = m

	return e
}

func (g *gatherer) hydrateRepeatedFieldType(s *scalarT) FieldType {
	r := &repT{scalarT: s}
	r.el = &scalarE{
		typ:   r,
		ptype: r.ProtoType(),
		name:  r.Name().Element(),
	}

	switch s.ProtoType() {
	case EnumT:
		ent, ok := g.seenObj(g.Generator.ObjectNamed(s.fld.Descriptor().GetTypeName()))
		g.Assert(ok, "enum type not seen")

		en, ok := ent.(Enum)
		g.Assert(ok, "unexpected entity type")

		r.el = &enumE{
			scalarE: r.el.(*scalarE),
			enum:    en,
		}
	case MessageT:
		ent, ok := g.seenObj(g.Generator.ObjectNamed(s.fld.Descriptor().GetTypeName()))
		g.Assert(ok, "embed type not seen")

		m, ok := ent.(Message)
		g.Assert(ok, "unexpected entity type")

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

func (g *gatherer) hydrateMapFieldType(r *repT, m Message) FieldType {
	mt := &mapT{repT: r}

	mt.key = m.Fields()[0].Type().toElem()
	mt.key.setType(mt)

	mt.el = m.Fields()[1].Type().toElem()
	mt.el.setType(mt)

	mt.name = TypeName(fmt.Sprintf(
		"map[%s]%s",
		mt.key.Name(),
		mt.el.Name()))

	return mt
}

func (g *gatherer) hydrateOneOf(msg Message, idx int32, od *descriptor.OneofDescriptorProto) OneOf {
	o := &oneof{
		desc: od,
		msg:  msg,
	}

	if out, ok := g.seen(o); ok {
		return out.(*oneof)
	}
	g.add(o)

	g.push("oneof:" + o.Name().String())
	defer g.pop()

	o.comments = o.File().lookupComments(o.FullyQualifiedName())

	for _, f := range msg.Fields() {
		if i := f.Descriptor().OneofIndex; i != nil && idx == *i {
			o.addField(f)
		}
	}

	return o
}

func (g *gatherer) hydrateEnum(parent ParentEntity, ed *descriptor.EnumDescriptorProto) Enum {
	e := &enum{
		rawDesc: ed,
		parent:  parent,
	}

	if out, ok := g.seen(e); ok {
		return out.(*enum)
	}
	g.add(e)

	g.push("enum:" + e.Name().String())
	defer g.pop()

	name := e.FullyQualifiedName()
	e.genDesc = g.Generator.ObjectNamed(name).(*generator.EnumDescriptor)
	e.comments = e.File().lookupComments(name)

	for _, vd := range ed.GetValue() {
		e.addValue(g.hydrateEnumValue(e, vd))
	}

	return e
}

func (g *gatherer) hydrateEnumValue(parent Enum, vd *descriptor.EnumValueDescriptorProto) EnumValue {
	ev := &enumVal{
		desc: vd,
		enum: parent,
	}

	if out, ok := g.seen(ev); ok {
		return out.(*enumVal)
	}
	g.add(ev)

	ev.comments = ev.File().lookupComments(ev.FullyQualifiedName())

	return ev
}

func (g *gatherer) hydrateService(parent File, sd *descriptor.ServiceDescriptorProto) Service {
	s := &service{
		desc: sd,
		file: parent,
	}

	if out, ok := g.seen(s); ok {
		return out.(*service)
	}
	g.add(s)

	g.push("service:" + s.Name().String())
	defer g.pop()

	s.comments = s.File().lookupComments(s.FullyQualifiedName())

	for _, md := range sd.GetMethod() {
		s.addMethod(g.hydrateMethod(s, md))
	}

	return s
}

func (g *gatherer) hydrateMethod(parent Service, md *descriptor.MethodDescriptorProto) Method {
	m := &method{
		desc:    md,
		service: parent,
	}

	if out, ok := g.seen(m); ok {
		return out.(*method)
	}
	g.add(m)

	g.push("method:" + m.Name().String())
	defer g.pop()

	m.comments = m.File().lookupComments(m.FullyQualifiedName())

	in, ok := g.seenName(md.GetInputType())
	g.Assert(ok, "input type", md.GetInputType(), "not hydrated")
	m.in = in.(*msg)

	out, ok := g.seenName(md.GetOutputType())
	g.Assert(ok, "output type", md.GetOutputType(), "not hydrated")
	m.out = out.(*msg)

	return m
}

func (g *gatherer) push(prefix string) { g.BuildContext = g.Push(prefix) }

func (g *gatherer) pop() { g.BuildContext = g.Pop() }

func (g *gatherer) seen(e Entity) (Entity, bool) { return g.seenName(g.resolveFullyQualifiedName(e)) }

func (g *gatherer) seenName(ln string) (Entity, bool) {
	out, ok := g.entities[ln]
	return out, ok
}

func (g *gatherer) seenObj(o generator.Object) (Entity, bool) {
	ent, ok := g.seenName(o.File().GetName())
	g.Assert(ok, "dependent proto file not seen:", o.File().GetName())
	fl := ent.File()

	return g.seenName(fl.FullyQualifiedName() + "." + strings.Join(o.TypeName(), "."))
}

func (g *gatherer) add(e Entity) { g.entities[g.resolveFullyQualifiedName(e)] = e }

func (g *gatherer) resolveFullyQualifiedName(e Entity) string {
	if f, ok := e.(File); ok {
		return f.Name().String()
	}

	return e.FullyQualifiedName()
}

func (g *gatherer) nameByPath(f *descriptor.FileDescriptorProto, path []int32) (string, error) {
	const (
		packagePath     = 2 // FileDescriptorProto.Package
		messageTypePath = 4 // FileDescriptorProto.MessageType
		enumTypePath    = 5 // FileDescriptorProto.EnumType
		servicePath     = 6 // FileDescriptorProto.Service

		messageTypeFieldPath      = 2 // DescriptorProto.Field
		messageTypeNestedTypePath = 3 // DescriptorProto.NestedType
		messageTypeEnumTypePath   = 4 // DescriptorProto.EnumType
		messageTypeOneofDeclPath  = 8 // DescriptorProto.OneofDecl
	)

	// return fast in case it's the package leading comment
	packageName := f.GetPackage()
	if path[0] == packagePath {
		return fmt.Sprintf(".%s", packageName), nil
	}

	// as we're refering to concrete entities, entity type should be followed by
	// an index number thus always leading to even paths.
	if len(path)%2 != 0 {
		return "", errors.New("path must have even elements")
	}

	// tail-call recursive path to name conversion functor
	var fn func(interface {
		GetName() string
	}, []int32, *[]string) error
	fn = func(parent interface {
		GetName() string
	}, path []int32, names *[]string) error {
		if len(path) == 0 {
			return nil
		}

		t := path[0]
		n := path[1]
		switch td := parent.(type) {
		case *descriptor.FileDescriptorProto:
			switch t {
			case messageTypePath:
				parent = td.MessageType[n]
			case enumTypePath:
				parent = td.EnumType[n]
			case servicePath:
				parent = td.Service[n]
			}
		case *descriptor.ServiceDescriptorProto:
			parent = td.Method[n]
		case *descriptor.EnumDescriptorProto:
			parent = td.Value[n]
		case *descriptor.DescriptorProto:
			switch t {
			case messageTypeFieldPath:
				parent = td.Field[n]
			case messageTypeNestedTypePath:
				parent = td.NestedType[n]
			case messageTypeEnumTypePath:
				parent = td.EnumType[n]
			case messageTypeOneofDeclPath:
				parent = td.OneofDecl[n]
			}
		}

		*names = append(*names, parent.GetName())
		return fn(parent, path[2:], names)
	}

	// reserve exactly the required capacity
	var names []string
	namesLen := uint(len(path) / 2)
	if packageName != "" {
		names = make([]string, 0, namesLen+1)
		names = append(names, packageName)
	} else {
		names = make([]string, 0, namesLen)
	}

	// start the conversion
	err := fn(f, path, &names)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(".%s", strings.Join(names, ".")), nil
}

var _ generator.Plugin = (*gatherer)(nil)
