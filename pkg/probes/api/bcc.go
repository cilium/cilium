// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"fmt"
	"io/ioutil"
	"path"

	"github.com/cilium/cilium/pkg/option"

	"github.com/iovisor/gobpf/bcc"
	"github.com/sirupsen/logrus"
)

// ProbeAttachment is an attachenment of a function of ProbeProg to a probe
type ProbeAttachment struct {
	// Typ is the type of probe to attach to
	Typ ProbeType

	// ProbeName is the name fo the probe to attach to
	ProbeName string

	// FuncName is the name of the function in SourceFilename to call
	// when the probe is invoked
	FuncName string

	// fd refers to the compiled program and points to FuncName
	fd int
}

func (a *ProbeAttachment) getLogger(scopedLog *logrus.Entry) *logrus.Entry {
	return scopedLog.WithFields(logrus.Fields{
		probeType: a.Typ,
		probeName: a.ProbeName,
		funcName:  a.FuncName,
	})
}

// ProbeProg consists of a source program with functions and a list of probe
// attachments, attaching probes to those functions.
type ProbeProg struct {
	// SourceFilename is the filename of the source file in the BpfDir
	SourceFilename string

	// Probes is the list of probes to attach to
	Probes []ProbeAttachment

	// Module is the BCC module backing the prog
	Module *bcc.Module
}

func (p *ProbeProg) getLogger() *logrus.Entry {
	return log.WithFields(logrus.Fields{
		sourceFilename: p.SourceFilename,
	})
}

type ProbeProgInterface interface {
	LoadAndAttach() error
	Close()
	getSourceFilename() string
}

// LoadAndAttach loads the source code, compiles the programs and attachs the
// probes. The probes are only attached if all programs can be compiled.
func (p *ProbeProg) LoadAndAttach() error {
	scopedLog := p.getLogger()
	scopedLog.Debugf("Loading prog with %d probes", len(p.Probes))

	sourcePath := path.Join(option.Config.BpfDir, p.SourceFilename)
	source, err := ioutil.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("unable to read source file %s: %s", sourcePath, err)
	}

	cflags := []string{
		fmt.Sprintf("-I%s", option.Config.BpfDir),
	}
	m := bcc.NewModule(string(source), cflags)
	if m == nil {
		return fmt.Errorf("bcc returned a nil module")
	}

	p.Module = m

	defer func() {
		if err != nil {
			m.Close()
		}
	}()

	for i, probe := range p.Probes {
		probe.getLogger(scopedLog).Debug("Initializing BPF probe")

		switch probe.Typ {
		case KProbeType, KRetProbeType:
			fd, err := m.LoadKprobe(probe.FuncName)
			if err != nil {
				return fmt.Errorf("failed to load function %s of kprobe prog: %s",
					probe.FuncName, err)
			}

			p.Probes[i].fd = fd
		default:
			return fmt.Errorf("Unknown probe type %+v", probe.Typ)
		}
	}

	for _, probe := range p.Probes {
		var err error

		switch probe.Typ {
		case KProbeType:
			err = m.AttachKprobe(probe.ProbeName, probe.fd)
		case KRetProbeType:
			err = m.AttachKretprobe(probe.ProbeName, probe.fd)
		}

		if err != nil {
			return fmt.Errorf("unable to attach to %s %s: %s",
				probe.Typ, probe.ProbeName, err)
		}

		probe.getLogger(scopedLog).Debug("Attached BPF prog to probe")
	}

	return nil
}

// Close releases all resources of the ProbeProg
func (p *ProbeProg) Close() {
	if p.Module != nil {
		p.Module.Close()
	}
}

func (p *ProbeProg) getSourceFilename() string {
	return p.SourceFilename
}
