package pgs

import (
	"io/ioutil"
	"sync"

	"github.com/golang/protobuf/proto"
	plugin_go "github.com/golang/protobuf/protoc-gen-go/plugin"
)

type workflow interface {
	Init(*Generator) AST
	Run(AST) []Artifact
	Persist([]Artifact)
}

// standardWorkflow describes a typical protoc-plugin flow, with the only
// exception being the behavior of the persister directly writing custom file
// artifacts to disk (instead of via the plugin's output to protoc).
type standardWorkflow struct {
	*Generator
	BiDi bool
}

func (wf *standardWorkflow) Init(g *Generator) AST {
	wf.Generator = g

	wf.Debug("reading input")
	data, err := ioutil.ReadAll(g.in)
	wf.CheckErr(err, "reading input")

	wf.Debug("parsing input proto")
	req := new(plugin_go.CodeGeneratorRequest)
	err = proto.Unmarshal(data, req)
	wf.CheckErr(err, "parsing input proto")
	wf.Assert(len(req.FileToGenerate) > 0, "no files to generate")

	wf.Debug("parsing command-line params")
	wf.params = ParseParameters(req.GetParameter())
	for _, pm := range wf.paramMutators {
		pm(wf.params)
	}

	if wf.BiDi {
		return ProcessCodeGeneratorRequestBidirectional(g, req)
	}

	return ProcessCodeGeneratorRequest(g, req)
}

func (wf *standardWorkflow) Run(ast AST) (arts []Artifact) {
	ctx := Context(wf.Debugger, wf.params, wf.params.OutputPath())

	wf.Debug("initializing modules")
	for _, m := range wf.mods {
		m.InitContext(ctx.Push(m.Name()))
	}

	wf.Debug("executing modules")
	for _, m := range wf.mods {
		arts = append(arts, m.Execute(ast.Targets(), ast.Packages())...)
	}

	return
}

func (wf *standardWorkflow) Persist(arts []Artifact) {
	resp := wf.persister.Persist(arts...)

	data, err := proto.Marshal(resp)
	wf.CheckErr(err, "marshaling output proto")

	n, err := wf.out.Write(data)
	wf.CheckErr(err, "writing output proto")
	wf.Assert(len(data) == n, "failed to write all output")

	wf.Debug("rendering successful")
}

// onceWorkflow wraps an existing workflow, executing its methods exactly
// once. Subsequent calls will ignore their inputs and use the previously
// provided values.
type onceWorkflow struct {
	workflow

	initOnce sync.Once
	ast      AST

	runOnce sync.Once
	arts    []Artifact

	persistOnce sync.Once
}

func (wf *onceWorkflow) Init(g *Generator) AST {
	wf.initOnce.Do(func() { wf.ast = wf.workflow.Init(g) })
	return wf.ast
}

func (wf *onceWorkflow) Run(ast AST) []Artifact {
	wf.runOnce.Do(func() {
		wf.arts = wf.workflow.Run(ast)
	})
	return wf.arts
}

func (wf *onceWorkflow) Persist(artifacts []Artifact) {
	wf.persistOnce.Do(func() { wf.workflow.Persist(artifacts) })
}
