package pgs

import (
	"io"
	"log"
	"os"
)

// Generator configures and executes a protoc plugin's lifecycle.
type Generator struct {
	Debugger

	persister persister // handles writing artifacts to their output
	workflow  workflow

	mods []Module // registered pg* modules

	in  io.Reader // protoc input reader
	out io.Writer // protoc output writer

	debug bool // whether or not to print debug messages

	params        Parameters     // CLI parameters passed in from protoc
	paramMutators []ParamMutator // registered param mutators
}

// Init configures a new Generator. InitOptions may be provided as well to
// modify the behavior of the generator.
func Init(opts ...InitOption) *Generator {
	g := &Generator{
		in:        os.Stdin,
		out:       os.Stdout,
		persister: newPersister(),
		workflow:  &onceWorkflow{workflow: &standardWorkflow{}},
	}

	for _, opt := range opts {
		opt(g)
	}

	g.Debugger = initDebugger(g.debug, log.New(os.Stderr, "", 0))
	g.persister.SetDebugger(g.Debugger)

	return g
}

// RegisterModule should be called before Render to attach a custom Module to
// the Generator. This method can be called multiple times.
func (g *Generator) RegisterModule(m ...Module) *Generator {
	for _, mod := range m {
		g.Assert(mod != nil, "nil module provided")
		g.Debug("registering module: ", mod.Name())
	}

	g.mods = append(g.mods, m...)
	return g
}

// RegisterPostProcessor should be called before Render to attach
// PostProcessors to the Generator. This method can be called multiple times.
// PostProcessors are executed against their matches in the order in which they
// are registered.
func (g *Generator) RegisterPostProcessor(p ...PostProcessor) *Generator {
	for _, pp := range p {
		g.Assert(pp != nil, "nil post-processor provided")
	}
	g.persister.AddPostProcessor(p...)
	return g
}

// AST returns the constructed AST graph from the gatherer. This method is
// idempotent, can be called multiple times (before and after calls to Render,
// even), and is particularly useful in testing.
func (g *Generator) AST() AST {
	return g.workflow.Init(g)
}

// Render executes the protoc plugin flow, gathering the AST from the input
// io.Reader (typically stdin via protoc), running all the registered modules,
// and persisting the generated artifacts to the output io.Writer (typically
// stdout to protoc + direct file system writes for custom artifacts). This
// method is idempotent, in that subsequent calls to Render will have no
// effect.
func (g *Generator) Render() {
	ast := g.workflow.Init(g)
	arts := g.workflow.Run(ast)
	g.workflow.Persist(arts)
}

func (g *Generator) push(prefix string) { g.Debugger = g.Push(prefix) }
func (g *Generator) pop()               { g.Debugger = g.Pop() }
