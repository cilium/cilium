package pgs

import (
	"os"
	"path/filepath"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/protoc-gen-go/plugin"
	"github.com/spf13/afero"
)

type persister interface {
	SetDebugger(d Debugger)
	SetPGG(pgg ProtocGenGo)
	SetFS(fs afero.Fs)
	AddPostProcessor(proc ...PostProcessor)
	Persist(a ...Artifact)
}

type stdPersister struct {
	Debugger

	pgg   ProtocGenGo
	fs    afero.Fs
	procs []PostProcessor
}

func newPersister() *stdPersister { return &stdPersister{fs: afero.NewOsFs()} }

func (p *stdPersister) SetDebugger(d Debugger)                 { p.Debugger = d }
func (p *stdPersister) SetPGG(pgg ProtocGenGo)                 { p.pgg = pgg }
func (p *stdPersister) SetFS(fs afero.Fs)                      { p.fs = fs }
func (p *stdPersister) AddPostProcessor(proc ...PostProcessor) { p.procs = append(p.procs, proc...) }

func (p *stdPersister) Persist(arts ...Artifact) {
	for _, a := range arts {
		switch a := a.(type) {
		case GeneratorFile:
			f, err := a.ProtoFile()
			p.CheckErr(err, "unable to convert ", a.Name, " to proto")
			f.Content = proto.String(p.postProcess(a, f.GetContent()))
			p.insertFile(f, a.Overwrite)
		case GeneratorTemplateFile:
			f, err := a.ProtoFile()
			p.CheckErr(err, "unable to convert ", a.Name, " to proto")
			f.Content = proto.String(p.postProcess(a, f.GetContent()))
			p.insertFile(f, a.Overwrite)
		case GeneratorAppend:
			f, err := a.ProtoFile()
			p.CheckErr(err, "unable to convert append for ", a.FileName, " to proto")
			f.Content = proto.String(p.postProcess(a, f.GetContent()))
			n, _ := cleanGeneratorFileName(a.FileName)
			p.insertAppend(n, f)
		case GeneratorTemplateAppend:
			f, err := a.ProtoFile()
			p.CheckErr(err, "unable to convert append for ", a.FileName, " to proto")
			f.Content = proto.String(p.postProcess(a, f.GetContent()))
			n, _ := cleanGeneratorFileName(a.FileName)
			p.insertAppend(n, f)
		case GeneratorInjection:
			f, err := a.ProtoFile()
			p.CheckErr(err, "unable to convert injection ", a.InsertionPoint, " for ", a.FileName, " to proto")
			f.Content = proto.String(p.postProcess(a, f.GetContent()))
			p.insertFile(f, false)
		case GeneratorTemplateInjection:
			f, err := a.ProtoFile()
			p.CheckErr(err, "unable to convert injection ", a.InsertionPoint, " for ", a.FileName, " to proto")
			f.Content = proto.String(p.postProcess(a, f.GetContent()))
			p.insertFile(f, false)
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
		default:
			p.Failf("unrecognized artifact type: %T", a)
		}
	}
}

func (p *stdPersister) indexOfFile(name string) int {
	for i, f := range p.pgg.response().GetFile() {
		if f.GetName() == name && f.InsertionPoint == nil {
			return i
		}
	}

	return -1
}

func (p *stdPersister) insertFile(f *plugin_go.CodeGeneratorResponse_File, overwrite bool) {
	if overwrite {
		if i := p.indexOfFile(f.GetName()); i >= 0 {
			p.pgg.response().File[i] = f
			return
		}
	}

	p.pgg.response().File = append(p.pgg.response().File, f)
}

func (p *stdPersister) insertAppend(name string, f *plugin_go.CodeGeneratorResponse_File) {
	i := p.indexOfFile(name)
	p.Assert(i > -1, "append target ", name, " missing")

	p.pgg.response().File = append(
		p.pgg.response().File[:i+1],
		append(
			[]*plugin_go.CodeGeneratorResponse_File{f},
			p.pgg.response().File[i+1:]...,
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
