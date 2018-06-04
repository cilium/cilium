package pgs

import (
	"io/ioutil"

	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/protoc-gen-go/plugin"
)

type workflow interface {
	Init(g *Generator)
	Go()
	Star()
	Persist()
}

// standardWorkflow uses a close-to-official execution pattern for PGGo. PG*
// modules are executed once the PGGo execution has completed and files are
// persisted the Generator's Persister instance (typically sending back to
// protoc and creating files on disk).
type standardWorkflow struct {
	*Generator
	arts []Artifact
}

func (wf *standardWorkflow) Init(g *Generator) {
	*wf = standardWorkflow{}
	wf.Generator = g

	wf.Debug("reading input")
	data, err := ioutil.ReadAll(wf.in)
	wf.CheckErr(err, "reading input")

	wf.Debug("parsing input proto")
	err = proto.Unmarshal(data, wf.pgg.request())
	wf.CheckErr(err, "parsing input proto")
	wf.Assert(len(wf.pgg.request().FileToGenerate) > 0, "no files to generate")

	wf.Debug("parsing command-line params")
	wf.params = ParseParameters(wf.pgg.request().GetParameter())
	for _, pm := range wf.paramMutators {
		pm(wf.params)
	}
}

func (wf *standardWorkflow) Go() {
	wf.RegisterPlugin(wf.gatherer)
	wf.params.AddPlugin(wf.gatherer.Name())

	wf.Debug("initializing plugins")
	for _, p := range wf.plugins {
		p.InitContext(Context(
			wf.Debugger.Push(p.Name()),
			wf.params,
			".",
		))
	}

	wf.Debug("preparing official generator")
	wf.pgg.prepare(wf.params)

	wf.Debug("generating official PGG PBs and gathering PG* AST")
	wf.pgg.generate()
}

func (wf *standardWorkflow) Star() {
	ctx := Context(wf.Debugger, wf.params, wf.params.OutputPath())

	wf.Debug("initializing modules")
	for _, m := range wf.mods {
		m.InitContext(ctx.Push(m.Name()))
	}

	wf.Debug("executing modules")
	for _, m := range wf.mods {
		if mm, ok := m.(MultiModule); ok {
			wf.arts = append(wf.arts, mm.MultiExecute(wf.gatherer.targets, wf.gatherer.pkgs)...)
		} else {
			for _, pkg := range wf.gatherer.targets {
				wf.arts = append(wf.arts, m.Execute(pkg, wf.gatherer.pkgs)...)
			}
		}
	}
}

func (wf *standardWorkflow) Persist() {
	wf.persister.Persist(wf.arts...)

	data, err := proto.Marshal(wf.pgg.response())
	wf.CheckErr(err, "marshaling output proto")

	n, err := wf.out.Write(data)
	wf.CheckErr(err, "writing output proto")
	wf.Assert(len(data) == n, "failed to write all output")

	wf.Debug("rendering successful")
}

// onceWorkflow wraps an existing workflow, executing its methods only once.
// This is required to keep the Generator AST & Render methods idempotent.
type onceWorkflow struct {
	workflow
	initOnce    sync.Once
	goOnce      sync.Once
	starOnce    sync.Once
	persistOnce sync.Once
}

func (wf *onceWorkflow) Init(g *Generator) { wf.initOnce.Do(func() { wf.workflow.Init(g) }) }
func (wf *onceWorkflow) Go()               { wf.goOnce.Do(wf.workflow.Go) }
func (wf *onceWorkflow) Star()             { wf.starOnce.Do(wf.workflow.Star) }
func (wf *onceWorkflow) Persist()          { wf.persistOnce.Do(wf.workflow.Persist) }

// excludeGoWorkflow wraps an existing workflow, stripping any PGGo generated
// files from the response. This workflow is used when the IncludeGo InitOption
// is not applied to the Generator.
type excludeGoWorkflow struct {
	*Generator
	workflow
}

func (wf *excludeGoWorkflow) Init(g *Generator) {
	wf.Generator = g
	wf.workflow.Init(g)
}

func (wf *excludeGoWorkflow) Go() {
	wf.workflow.Go()

	scrubbed := make(
		[]*plugin_go.CodeGeneratorResponse_File,
		0, len(wf.pgg.response().File))

	toScrub := make(map[string]struct{}, len(wf.pgg.response().File))
	el := struct{}{}

	for _, pkg := range wf.gatherer.targets {
		for _, f := range pkg.Files() {
			if f.BuildTarget() {
				toScrub[f.OutputPath().String()] = el
			}
		}
	}

	for _, f := range wf.pgg.response().File {
		if _, scrub := toScrub[f.GetName()]; !scrub {
			scrubbed = append(scrubbed, f)
		} else {
			wf.Debug("excluding official Go PB:", f.GetName())
		}
	}

	wf.pgg.response().File = scrubbed
}
