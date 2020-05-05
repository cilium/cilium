package pgs

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/golang/protobuf/proto"
	plugin_go "github.com/golang/protobuf/protoc-gen-go/plugin"
	"github.com/spf13/afero"
)

type persister interface {
	SetDebugger(d Debugger)
	SetFS(fs afero.Fs)
	AddPostProcessor(proc ...PostProcessor)
	Persist(a ...Artifact) *plugin_go.CodeGeneratorResponse
}

type stdPersister struct {
	Debugger

	fs    afero.Fs
	procs []PostProcessor
}

func newPersister() *stdPersister { return &stdPersister{fs: afero.NewOsFs()} }

func (p *stdPersister) SetDebugger(d Debugger)                 { p.Debugger = d }
func (p *stdPersister) SetFS(fs afero.Fs)                      { p.fs = fs }
func (p *stdPersister) AddPostProcessor(proc ...PostProcessor) { p.procs = append(p.procs, proc...) }

func (p *stdPersister) Persist(arts ...Artifact) *plugin_go.CodeGeneratorResponse {
	resp := new(plugin_go.CodeGeneratorResponse)

	for _, a := range arts {
		switch a := a.(type) {
		case GeneratorFile:
			f, err := a.ProtoFile()
			p.CheckErr(err, "unable to convert ", a.Name, " to proto")
			f.Content = proto.String(p.postProcess(a, f.GetContent()))
			p.insertFile(resp, f, a.Overwrite)
		case GeneratorTemplateFile:
			f, err := a.ProtoFile()
			p.CheckErr(err, "unable to convert ", a.Name, " to proto")
			f.Content = proto.String(p.postProcess(a, f.GetContent()))
			p.insertFile(resp, f, a.Overwrite)
		case GeneratorAppend:
			f, err := a.ProtoFile()
			p.CheckErr(err, "unable to convert append for ", a.FileName, " to proto")
			f.Content = proto.String(p.postProcess(a, f.GetContent()))
			n, _ := cleanGeneratorFileName(a.FileName)
			p.insertAppend(resp, n, f)
		case GeneratorTemplateAppend:
			f, err := a.ProtoFile()
			p.CheckErr(err, "unable to convert append for ", a.FileName, " to proto")
			f.Content = proto.String(p.postProcess(a, f.GetContent()))
			n, _ := cleanGeneratorFileName(a.FileName)
			p.insertAppend(resp, n, f)
		case GeneratorInjection:
			f, err := a.ProtoFile()
			p.CheckErr(err, "unable to convert injection ", a.InsertionPoint, " for ", a.FileName, " to proto")
			f.Content = proto.String(p.postProcess(a, f.GetContent()))
			p.insertFile(resp, f, false)
		case GeneratorTemplateInjection:
			f, err := a.ProtoFile()
			p.CheckErr(err, "unable to convert injection ", a.InsertionPoint, " for ", a.FileName, " to proto")
			f.Content = proto.String(p.postProcess(a, f.GetContent()))
			p.insertFile(resp, f, false)
		case CustomFile:
			p.writeFile(
				a.Name,
				[]byte(p.postProcess(a, a.Contents)),
				a.Overwrite,
				a.Perms,
			)
		case CustomTemplateFile:
			content, err := a.render()
			p.CheckErr(err, "unable to render CustomTemplateFile: ", a.Name)
			content = p.postProcess(a, content)
			p.writeFile(
				a.Name,
				[]byte(content),
				a.Overwrite,
				a.Perms,
			)
		case GeneratorError:
			if resp.Error == nil {
				resp.Error = proto.String(a.Message)
				continue
			}
			resp.Error = proto.String(strings.Join([]string{resp.GetError(), a.Message}, "; "))
		default:
			p.Failf("unrecognized artifact type: %T", a)
		}
	}

	return resp
}

func (p *stdPersister) indexOfFile(resp *plugin_go.CodeGeneratorResponse, name string) int {
	for i, f := range resp.GetFile() {
		if f.GetName() == name && f.InsertionPoint == nil {
			return i
		}
	}

	return -1
}

func (p *stdPersister) insertFile(resp *plugin_go.CodeGeneratorResponse,
	f *plugin_go.CodeGeneratorResponse_File, overwrite bool) {
	if overwrite {
		if i := p.indexOfFile(resp, f.GetName()); i >= 0 {
			resp.File[i] = f
			return
		}
	}

	resp.File = append(resp.File, f)
}

func (p *stdPersister) insertAppend(resp *plugin_go.CodeGeneratorResponse,
	name string, f *plugin_go.CodeGeneratorResponse_File) {
	i := p.indexOfFile(resp, name)
	p.Assert(i > -1, "append target ", name, " missing")

	resp.File = append(
		resp.File[:i+1],
		append(
			[]*plugin_go.CodeGeneratorResponse_File{f},
			resp.File[i+1:]...,
		)...,
	)
}

func (p *stdPersister) writeFile(name string, content []byte, overwrite bool, perms os.FileMode) {
	dir := filepath.Dir(name)
	p.CheckErr(
		p.fs.MkdirAll(dir, 0755),
		"unable to create directory:", dir)

	exists, err := afero.Exists(p.fs, name)
	p.CheckErr(err, "unable to check file exists:", name)

	if exists {
		if !overwrite {
			p.Debug("file", name, "exists, skipping")
			return
		}
		p.Debug("file", name, "exists, overwriting")
	}

	p.CheckErr(
		afero.WriteFile(p.fs, name, content, perms),
		"unable to write file:", name)
}

func (p *stdPersister) postProcess(a Artifact, in string) string {
	var err error
	b := []byte(in)
	for _, pp := range p.procs {
		if pp.Match(a) {
			b, err = pp.Process(b)
			p.CheckErr(err, "failed post-processing")
		}
	}

	return string(b)
}
