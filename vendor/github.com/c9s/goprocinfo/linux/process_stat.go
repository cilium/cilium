package linux

import (
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
)

// Status information about the process.
type ProcessStat struct {
	Pid                 uint64 `json:"pid"`
	Comm                string `json:"comm"`
	State               string `json:"state"`
	Ppid                int64  `json:"ppid"`
	Pgrp                int64  `json:"pgrp"`
	Session             int64  `json:"session"`
	TtyNr               int64  `json:"tty_nr"`
	Tpgid               int64  `json:"tpgid"`
	Flags               uint64 `json:"flags"`
	Minflt              uint64 `json:"minflt"`
	Cminflt             uint64 `json:"cminflt"`
	Majflt              uint64 `json:"majflt"`
	Cmajflt             uint64 `json:"cmajflt"`
	Utime               uint64 `json:"utime"`
	Stime               uint64 `json:"stime"`
	Cutime              int64  `json:"cutime"`
	Cstime              int64  `json:"cstime"`
	Priority            int64  `json:"priority"`
	Nice                int64  `json:"nice"`
	NumThreads          int64  `json:"num_threads"`
	Itrealvalue         int64  `json:"itrealvalue"`
	Starttime           uint64 `json:"starttime"`
	Vsize               uint64 `json:"vsize"`
	Rss                 int64  `json:"rss"`
	Rsslim              uint64 `json:"rsslim"`
	Startcode           uint64 `json:"startcode"`
	Endcode             uint64 `json:"endcode"`
	Startstack          uint64 `json:"startstack"`
	Kstkesp             uint64 `json:"kstkesp"`
	Kstkeip             uint64 `json:"kstkeip"`
	Signal              uint64 `json:"signal"`
	Blocked             uint64 `json:"blocked"`
	Sigignore           uint64 `json:"sigignore"`
	Sigcatch            uint64 `json:"sigcatch"`
	Wchan               uint64 `json:"wchan"`
	Nswap               uint64 `json:"nswap"`
	Cnswap              uint64 `json:"cnswap"`
	ExitSignal          int64  `json:"exit_signal"`
	Processor           int64  `json:"processor"`
	RtPriority          uint64 `json:"rt_priority"`
	Policy              uint64 `json:"policy"`
	DelayacctBlkioTicks uint64 `json:"delayacct_blkio_ticks"`
	GuestTime           uint64 `json:"guest_time"`
	CguestTime          int64  `json:"cguest_time"`
	StartData           uint64 `json:"start_data"`
	EndData             uint64 `json:"end_data"`
	StartBrk            uint64 `json:"start_brk"`
	ArgStart            uint64 `json:"arg_start"`
	ArgEnd              uint64 `json:"arg_end"`
	EnvStart            uint64 `json:"env_start"`
	EnvEnd              uint64 `json:"env_end"`
	ExitCode            int64  `json:"exit_code"`
}

var processStatRegExp = regexp.MustCompile("^(\\d+)( \\(.*?\\) )(.*)$")

func ReadProcessStat(path string) (*ProcessStat, error) {

	b, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	s := string(b)

	f := make([]string, 0, 32)

	e := processStatRegExp.FindStringSubmatch(strings.TrimSpace(s))

	// Inject process Pid
	f = append(f, e[1])

	// Inject process Comm
	f = append(f, strings.TrimSpace(e[2]))

	// Inject all remaining process info
	f = append(f, (strings.Fields(e[3]))...)

	stat := ProcessStat{}

	for i := 0; i < len(f); i++ {
		switch i {
		case 0:
			if stat.Pid, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 1:
			stat.Comm = f[i]
		case 2:
			stat.State = f[i]
		case 3:
			if stat.Ppid, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 4:
			if stat.Pgrp, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 5:
			if stat.Session, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 6:
			if stat.TtyNr, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 7:
			if stat.Tpgid, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 8:
			if stat.Flags, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 9:
			if stat.Minflt, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 10:
			if stat.Cminflt, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 11:
			if stat.Majflt, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 12:
			if stat.Cmajflt, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 13:
			if stat.Utime, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 14:
			if stat.Stime, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 15:
			if stat.Cutime, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 16:
			if stat.Cstime, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 17:
			if stat.Priority, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 18:
			if stat.Nice, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 19:
			if stat.NumThreads, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 20:
			if stat.Itrealvalue, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 21:
			if stat.Starttime, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 22:
			if stat.Vsize, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 23:
			if stat.Rss, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 24:
			if stat.Rsslim, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 25:
			if stat.Startcode, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 26:
			if stat.Endcode, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 27:
			if stat.Startstack, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 28:
			if stat.Kstkesp, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 29:
			if stat.Kstkeip, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 30:
			if stat.Signal, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 31:
			if stat.Blocked, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 32:
			if stat.Sigignore, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 33:
			if stat.Sigcatch, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 34:
			if stat.Wchan, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 35:
			if stat.Nswap, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 36:
			if stat.Cnswap, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 37:
			if stat.ExitSignal, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 38:
			if stat.Processor, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 39:
			if stat.RtPriority, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 40:
			if stat.Policy, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 41:
			if stat.DelayacctBlkioTicks, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 42:
			if stat.GuestTime, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 43:
			if stat.CguestTime, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 44:
			if stat.StartData, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 45:
			if stat.EndData, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 46:
			if stat.StartBrk, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 47:
			if stat.ArgStart, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 48:
			if stat.ArgEnd, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 49:
			if stat.EnvStart, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 50:
			if stat.EnvEnd, err = strconv.ParseUint(f[i], 10, 64); err != nil {
				return nil, err
			}
		case 51:
			if stat.ExitCode, err = strconv.ParseInt(f[i], 10, 64); err != nil {
				return nil, err
			}
		}
	}

	return &stat, nil
}
