package pgs

import (
	"io"
	"log"
	"os"
	"strconv"
	"text/template"

	"github.com/golang/protobuf/protoc-gen-go/generator"
)

// Plugin describes an official protoc-gen-go plugin that will also be passed a
// pre-configured debugger for use. The plugin must be registered via
// Generator.RegisterPlugin for it to be properly initialized.
type Plugin interface {
	generator.Plugin

	// InitContext is called before the Plugin's Init method and is passed a
	// pre-configured BuildContext instance.
	InitContext(c BuildContext)
}

// Template describes a template used to render content. Both the text/template
// and html/template packages satisfy this interface.
type Template interface {
	Name() string
	Execute(wr io.Writer, data interface{}) error
}

// PluginBase provides utility methods and a base implementation for the
// protoc-gen-go sub-plugin workflow.
type PluginBase struct {
	BuildContext

	Generator ProtocGenGo

	seenImports map[string]string
	Imports     map[string]string

	buildTargets map[string]struct{}
}

// Name satisfies the protoc-gen-go plugin interface, however this method will
// fail and must be overridden by a parent struct. PluginBase should be used as
// an anonymously embedded field of an actual Plugin implementation. The only
// methods that need to be overridden are Name and Generate.
func (p *PluginBase) Name() string {
	p.Fail("Name method is not implemented for this plugin")
	return "unimplemented"
}

// InitContext populates this Plugin with the BuildContext from the parent
// Generator, allowing for easy debug logging, and error checking. This
// method is called prior to Init for plugins registered directly with the
// generator.
func (p *PluginBase) InitContext(c BuildContext) { p.BuildContext = c }

// Init sets up the plugin with a reference to the generator. This method
// satisfies the Init method for the protoc-gen-go plugin.
func (p *PluginBase) Init(g *generator.Generator) {
	if p.BuildContext == nil {
		d := initDebugger(
			&Generator{pgg: Wrap(g)},
			log.New(os.Stderr, "", 0)).Push("unregistered plugin")
		p.BuildContext = Context(d, Parameters{}, ".")
	}

	p.Debug("Initializing")
	p.Generator = Wrap(g)
}

// Generate satisfies the protoc-gen-go plugin interface, however this method
// will fail and must be overridden by a parent struct.
func (p *PluginBase) Generate(file *generator.FileDescriptor) {
	p.Fail("Generate method is not implemented for this plugin")
}

var importsTmpl = template.Must(template.New("imports").Parse(`import({{ range $path, $pkg := . }}
	{{ $pkg }} "{{ $path }}"
{{- end }}
)`))

// GenerateImports adds the imported packages to the top of the file to be
// generated, using the packages included in b.Imports. This method satisfies
// the GenerateImports method for the protoc-gen-go plugin, and is called after
// Generate for each particular FileDescriptor. The added Imports are cleared
// after this call is completed.
func (p *PluginBase) GenerateImports(file *generator.FileDescriptor) {
	if p == nil || len(p.Imports) == 0 {
		return
	}
	p.T(importsTmpl, p.Imports)
	p.Imports = nil
}

// AddImport safely registers an import at path with the target pkg name. The
// returned uniquePkg should be used within the code to avoid naming collisions.
// If referencing an entity from a protocol buffer, provide its FileDescriptor
// fd, otherwise leave it as nil. The Imports are cleared after GenerateImports
// is called.
func (p *PluginBase) AddImport(pkg, path string, fd *generator.FileDescriptor) (uniquePkg string) {
	if p.seenImports == nil {
		p.seenImports = map[string]string{}
	}

	if p.Imports == nil {
		p.Imports = map[string]string{}
	}

	if existing, ok := p.seenImports[path]; ok {
		p.Imports[path] = existing
		return existing
	}

	uniquePkg = generator.RegisterUniquePackageName(pkg, fd)
	p.seenImports[path] = uniquePkg
	p.Imports[path] = uniquePkg

	return
}

// P wraps the generator's P method, printing the arguments to the generated
// output.  It handles strings and int32s, plus handling indirections because
// they may be *string, etc.
func (p *PluginBase) P(args ...interface{}) { p.Generator.P(args...) }

// In wraps the generator's In command, indenting the output by one tab.
func (p *PluginBase) In() { p.Generator.In() }

// Out wraps the generator's Out command, outdenting the output by one tab.
func (p *PluginBase) Out() { p.Generator.Out() }

// C behaves like the P method, but prints a comment block.
// The wrap parameter indicates what width to wrap the comment at.
func (p *PluginBase) C(wrap int, args ...interface{}) {
	s := commentScanner(wrap, args...)
	for s.Scan() {
		p.P("// ", s.Text())
	}
}

// C80 curries the C method with the traditional width of 80 characters,
// calling p.C(80, args...).
func (p *PluginBase) C80(args ...interface{}) { p.C(80, args...) }

// T renders tpl into the target file, using data. The plugin is terminated if
// there is an error executing the template. Both text/template and
// html/template packages are compatible with this method.
func (p *PluginBase) T(tpl Template, data interface{}) {
	p.CheckErr(
		tpl.Execute(p.Generator, data),
		"unable to render template: ",
		strconv.Quote(tpl.Name()))
}

// Push adds a prefix to the plugin's BuildContext. Pop should be called when
// that context is complete.
func (p *PluginBase) Push(prefix string) BuildContext {
	p.BuildContext = p.BuildContext.Push(prefix)
	return p.BuildContext
}

// PushDir changes the OutputPath of the plugin's BuildContext. Pop (or PopDir)
// should be called when that context is complete.
func (p *PluginBase) PushDir(dir string) BuildContext {
	p.BuildContext = p.BuildContext.PushDir(dir)
	return p.BuildContext
}

// Pop removes the last push from the plugin's BuildContext. This method should
// only be called after a paired Push or PushDir.
func (p *PluginBase) Pop() BuildContext {
	p.BuildContext = p.BuildContext.Pop()
	return p.BuildContext
}

// PopDir removes the last PushDir from the plugin's BuildContext. This method
// should only be called after a paired PushDir.
func (p *PluginBase) PopDir() BuildContext {
	p.BuildContext = p.BuildContext.PopDir()
	return p.BuildContext
}

// BuildTarget returns true if the specified proto filename was an input to
// protoc. This method is useful to determine if generation logic should be
// executed against it or if it is only loaded as a dependency. This method
// expects the value returned by generator.FileDescriptor.GetName or
// descriptor.FileDescriptorProto.GetName methods.
func (p *PluginBase) BuildTarget(proto string) bool {
	if p.buildTargets == nil {
		files := p.Generator.request().GetFileToGenerate()
		p.buildTargets = make(map[string]struct{}, len(files))
		for _, f := range files {
			p.buildTargets[f] = struct{}{}
		}
	}

	_, ok := p.buildTargets[proto]
	return ok
}

// BuildTargetObj returns whether or not a generator.Object was loaded from a
// BuildTarget file.
func (p *PluginBase) BuildTargetObj(o generator.Object) bool { return p.BuildTarget(o.File().GetName()) }

var _ Plugin = (*PluginBase)(nil)
