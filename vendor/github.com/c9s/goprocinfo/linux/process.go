package linux

import (
	"os"
	"path/filepath"
	"strconv"
)

type Process struct {
	Status  ProcessStatus `json:"status"`
	Statm   ProcessStatm  `json:"statm"`
	Stat    ProcessStat   `json:"stat"`
	IO      ProcessIO     `json:"io"`
	Cmdline string        `json:"cmdline"`
}

func ReadProcess(pid uint64, path string) (*Process, error) {

	var err error

	p := filepath.Join(path, strconv.FormatUint(pid, 10))

	if _, err = os.Stat(p); err != nil {
		return nil, err
	}

	process := Process{}

	var io *ProcessIO
	var stat *ProcessStat
	var statm *ProcessStatm
	var status *ProcessStatus
	var cmdline string

	if io, err = ReadProcessIO(filepath.Join(p, "io")); err != nil {
		return nil, err
	}

	if stat, err = ReadProcessStat(filepath.Join(p, "stat")); err != nil {
		return nil, err
	}

	if statm, err = ReadProcessStatm(filepath.Join(p, "statm")); err != nil {
		return nil, err
	}

	if status, err = ReadProcessStatus(filepath.Join(p, "status")); err != nil {
		return nil, err
	}

	if cmdline, err = ReadProcessCmdline(filepath.Join(p, "cmdline")); err != nil {
		return nil, err
	}

	process.IO = *io
	process.Stat = *stat
	process.Statm = *statm
	process.Status = *status
	process.Cmdline = cmdline

	return &process, nil
}
