package pgs

import (
	"bufio"
	"context"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"sync"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/protoc-gen-go/descriptor"
	protoc "github.com/golang/protobuf/protoc-gen-go/plugin"
	"golang.org/x/sync/errgroup"
)

const multiPackageSubProcessParam = "pgs_multipkg"

type multiPackageWorkflow struct {
	*Generator
	workflow

	stdout    io.Writer
	idxLookup map[string]int

	spoofFanout *protoc.CodeGeneratorResponse
}

func (wf *multiPackageWorkflow) Init(g *Generator) {
	wf.Generator = g
	wf.stdout = os.Stdout
	wf.workflow.Init(g)
}

func (wf *multiPackageWorkflow) Go() {
	wf.Debug("evaluating multi-package mode")

	if set, _ := wf.params.Bool(multiPackageSubProcessParam); set {
		wf.Debug("multi-package sub-process")
		wf.subGo()
		return
	}

	subReqs := wf.splitRequest()
	if len(subReqs) <= 1 {
		wf.Debug("single package run")
		wf.workflow.Go()
		return
	}

	wf.push("multi-package mode")
	defer wf.pop()
	wf.Debug("multiple packages detected")

	res := wf.fanoutSubReqs(subReqs)
	origReq := wf.pgg.request()

	wf.pgg.setRequest(&protoc.CodeGeneratorRequest{
		FileToGenerate: subReqs[0].FileToGenerate,
		ProtoFile:      wf.pgg.request().ProtoFile,
	})

	wf.RegisterPlugin(wf.gatherer)
	wf.gatherer.InitContext(Context(
		wf.Debugger.Push(wf.gatherer.Name()),
		wf.params,
		".",
	))

	params := ParseParameters(wf.params.String())
	params.SetStr(pluginsKey, wf.gatherer.Name())

	wf.pgg.prepare(params)
	wf.pgg.setRequest(origReq)

	wf.pgg.generate()
	wf.pgg.setResponse(res)
}

func (wf *multiPackageWorkflow) subGo() {
	wf.workflow.Go()

	data, err := proto.Marshal(wf.pgg.response())
	wf.CheckErr(err, "marshaling output proto")

	n, err := wf.stdout.Write(data)
	wf.CheckErr(err, "failed to write output")
	wf.Assert(n == len(data), "failed to write all output")

	wf.Debug("sub-process execution successful, forwarding back to main process")
	wf.Exit(0)
}

// splitRequest identifies sub-requests in the original PGG Request by
// individual directories. Since PGG expects only single-package requests, this
// identifies how many independent runs of PGG would be required.
func (wf *multiPackageWorkflow) splitRequest() (subReqs []*protoc.CodeGeneratorRequest) {
	wf.idxLookup = make(map[string]int, len(wf.pgg.request().ProtoFile))
	for i, f := range wf.pgg.request().ProtoFile {
		wf.idxLookup[f.GetName()] = i
	}

	params := ParseParameters(wf.params.String())
	params.SetBool(multiPackageSubProcessParam, true)

	fSets := wf.splitFileSets()
	subReqs = make([]*protoc.CodeGeneratorRequest, len(fSets))
	for i, fs := range fSets {
		subReqs[i] = &protoc.CodeGeneratorRequest{
			FileToGenerate: fs,
			ProtoFile:      wf.filterDeps(fs),
			Parameter:      proto.String(params.String()),
		}
	}

	return
}

// splitFileSets segments the FileToGenerate on the original PGG Request by
// directory, maintaining the order of execution.
func (wf *multiPackageWorkflow) splitFileSets() (out [][]string) {
	lu := map[string]int{}

	for _, f := range wf.pgg.request().FileToGenerate {
		dir := filepath.Dir(f)

		if i, ok := lu[dir]; ok {
			out[i] = append(out[i], f)
			continue
		}

		out = append(out, []string{f})
		lu[dir] = len(out) - 1
	}

	return
}

// filterDeps resolves the dependencies of just the files listed in fs from the
// ProtoFile slice on the original request, maintaining the order from the
// original.
func (wf *multiPackageWorkflow) filterDeps(fs []string) []*descriptor.FileDescriptorProto {
	var idxs []int

	for _, f := range fs {
		idxs = append(idxs, wf.resolveIndexes(f)...)
	}

	return wf.resolveProtos(idxs)
}

// resolveIndexes identifies the indexes of ProtoFile elements that are
// dependencies of the file f.
func (wf *multiPackageWorkflow) resolveIndexes(f string) []int {
	idx := wf.idxLookup[f]
	pb := wf.pgg.request().ProtoFile[idx]

	out := []int{idx}
	for _, d := range pb.Dependency {
		out = append(out, wf.resolveIndexes(d)...)
	}

	return out
}

// resolveProtos converts ProtoFile indexes into a subset of the ProtoFile.
// files are included in the output in the same order they appear in the
// original slice and duplicates are automatically removed.
func (wf *multiPackageWorkflow) resolveProtos(idxs []int) (out []*descriptor.FileDescriptorProto) {
	sort.Ints(idxs)
	last := -1

	for _, i := range idxs {
		if last == i {
			continue
		}

		out = append(out, wf.pgg.request().ProtoFile[i])
		last = i
	}

	return
}

// fanoutSubReqs spawns sub processes to individually execute each sub request
// provided. The resulting response is merged together if all requests are
// successful.
func (wf *multiPackageWorkflow) fanoutSubReqs(subReqs []*protoc.CodeGeneratorRequest) *protoc.CodeGeneratorResponse {
	if wf.spoofFanout != nil {
		return wf.spoofFanout
	}

	grp, ctx := errgroup.WithContext(context.Background())
	procs := wf.prepareProcesses(ctx, len(subReqs))
	return wf.handleProcesses(grp, procs, subReqs)
}

// prepareProcesses sets up n SubProcess instances for use in the workflow
func (wf *multiPackageWorkflow) prepareProcesses(ctx context.Context, n int) []subProcess {
	procs := make([]subProcess, n)
	for i := 0; i < n; i++ {
		procs[i] = exec.CommandContext(ctx, os.Args[0])
	}
	return procs
}

// handleProcesses multiplexes each of the sub-requests onto the provided procs
// and merges their responses into a single Response.
func (wf *multiPackageWorkflow) handleProcesses(
	grp *errgroup.Group,
	procs []subProcess,
	subReqs []*protoc.CodeGeneratorRequest,
) *protoc.CodeGeneratorResponse {
	outs := make([]*protoc.CodeGeneratorResponse, len(procs))

	for i, proc := range procs {
		p := proc
		req := subReqs[i]
		out := new(protoc.CodeGeneratorResponse)
		outs[i] = out

		grp.Go(func() error { return wf.handleProcess(p, req, out) })
	}

	wf.CheckErr(grp.Wait(), "execution of sub-processes failed")

	res := new(protoc.CodeGeneratorResponse)
	for _, out := range outs {
		res.File = append(res.File, out.File...)
	}

	return res
}

// handleProcess handles a single SubProcess execution
func (wf *multiPackageWorkflow) handleProcess(
	proc subProcess,
	req *protoc.CodeGeneratorRequest,
	res *protoc.CodeGeneratorResponse,
) error {
	stdin, err := proc.StdinPipe()
	if err != nil {
		return err
	}

	stdout, err := proc.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := proc.StderrPipe()
	if err != nil {
		return err
	}

	wg := &sync.WaitGroup{}
	wg.Add(3)

	var b []byte

	go func() {
		in, _ := proto.Marshal(req)
		stdin.Write(in)
		stdin.Close()
		wg.Done()
	}()

	go func() {
		b, _ = ioutil.ReadAll(stdout)
		wg.Done()
	}()

	go func() {
		sc := bufio.NewScanner(stderr)
		l := wf.Push(filepath.Dir(req.FileToGenerate[0]))
		for sc.Scan() {
			l.Log(sc.Text())
		}
		wg.Done()
	}()

	if err = proc.Start(); err != nil {
		return err
	}

	wg.Wait()

	if err = proc.Wait(); err != nil {
		return err
	}

	return proto.Unmarshal(b, res)
}

// subProcess is the interface used by Multi-Package workflow
type subProcess interface {
	Start() error
	Wait() error

	StdinPipe() (io.WriteCloser, error)
	StdoutPipe() (io.ReadCloser, error)
	StderrPipe() (io.ReadCloser, error)
}
