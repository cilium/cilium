package linux

import (
	"io/ioutil"
	"strconv"
	"strings"
)

// Provides much of the information from ProcessStatm and ProcessStat
type ProcessStatus struct {
	Name                     string
	State                    string
	Tgid                     uint64
	Pid                      uint64
	PPid                     int64
	TracerPid                uint64
	RealUid                  uint64
	EffectiveUid             uint64
	SavedSetUid              uint64
	FilesystemUid            uint64
	RealGid                  uint64
	EffectiveGid             uint64
	SavedSetGid              uint64
	FilesystemGid            uint64
	FDSize                   uint64
	Groups                   []int64
	VmPeak                   uint64
	VmSize                   uint64
	VmLck                    uint64
	VmHWM                    uint64
	VmRSS                    uint64
	VmData                   uint64
	VmStk                    uint64
	VmExe                    uint64
	VmLib                    uint64
	VmPTE                    uint64
	VmSwap                   uint64
	Threads                  uint64
	SigQLength               uint64
	SigQLimit                uint64
	SigPnd                   uint64
	ShdPnd                   uint64
	SigBlk                   uint64
	SigIgn                   uint64
	SigCgt                   uint64
	CapInh                   uint64
	CapPrm                   uint64
	CapEff                   uint64
	CapBnd                   uint64
	Seccomp                  uint8
	CpusAllowed              []uint32
	MemsAllowed              []uint32
	VoluntaryCtxtSwitches    uint64
	NonvoluntaryCtxtSwitches uint64
}

func ReadProcessStatus(path string) (*ProcessStatus, error) {

	b, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	status := ProcessStatus{}

	lines := strings.Split(string(b), "\n")

	for _, line := range lines {

		if strings.Index(line, ":") == -1 {
			continue
		}

		l := strings.Split(line, ":")

		k := strings.TrimSpace(l[0])
		v := strings.TrimSpace(l[1])

		switch k {
		case "Name":
			status.Name = v
		case "State":
			status.State = v
		case "Tgid":
			if status.Tgid, err = strconv.ParseUint(v, 10, 64); err != nil {
				return nil, err
			}
		case "Pid":
			if status.Pid, err = strconv.ParseUint(v, 10, 64); err != nil {
				return nil, err
			}
		case "PPid":
			if status.PPid, err = strconv.ParseInt(v, 10, 64); err != nil {
				return nil, err
			}
		case "TracerPid":
			if status.TracerPid, err = strconv.ParseUint(v, 10, 64); err != nil {
				return nil, err
			}
		case "Uid":
			if f := strings.Fields(v); len(f) == 4 {
				if status.RealUid, err = strconv.ParseUint(f[0], 10, 64); err != nil {
					return nil, err
				}
				if status.EffectiveUid, err = strconv.ParseUint(f[1], 10, 64); err != nil {
					return nil, err
				}
				if status.SavedSetUid, err = strconv.ParseUint(f[2], 10, 64); err != nil {
					return nil, err
				}
				if status.FilesystemUid, err = strconv.ParseUint(f[3], 10, 64); err != nil {
					return nil, err
				}
			}
		case "Gid":
			if f := strings.Fields(v); len(f) == 4 {
				if status.RealGid, err = strconv.ParseUint(f[0], 10, 64); err != nil {
					return nil, err
				}
				if status.EffectiveGid, err = strconv.ParseUint(f[1], 10, 64); err != nil {
					return nil, err
				}
				if status.SavedSetGid, err = strconv.ParseUint(f[2], 10, 64); err != nil {
					return nil, err
				}
				if status.FilesystemGid, err = strconv.ParseUint(f[3], 10, 64); err != nil {
					return nil, err
				}
			}
		case "FDSize":
			if status.FDSize, err = strconv.ParseUint(v, 10, 64); err != nil {
				return nil, err
			}
		case "Groups":
			{

				f := strings.Fields(v)
				status.Groups = make([]int64, len(f))

				for i := range status.Groups {
					if status.Groups[i], err = strconv.ParseInt(f[i], 10, 64); err != nil {
						return nil, err
					}
				}

			}
		case "VmPeak":
			{
				f := strings.Fields(v)
				if status.VmPeak, err = strconv.ParseUint(f[0], 10, 64); err != nil {
					return nil, err
				}
			}
		case "VmSize":
			{
				f := strings.Fields(v)
				if status.VmSize, err = strconv.ParseUint(f[0], 10, 64); err != nil {
					return nil, err
				}
			}
		case "VmLck":
			{
				f := strings.Fields(v)
				if status.VmLck, err = strconv.ParseUint(f[0], 10, 64); err != nil {
					return nil, err
				}
			}
		case "VmHWM":
			{
				f := strings.Fields(v)
				if status.VmHWM, err = strconv.ParseUint(f[0], 10, 64); err != nil {
					return nil, err
				}
			}
		case "VmRSS":
			{
				f := strings.Fields(v)
				if status.VmRSS, err = strconv.ParseUint(f[0], 10, 64); err != nil {
					return nil, err
				}
			}
		case "VmData":
			{
				f := strings.Fields(v)
				if status.VmData, err = strconv.ParseUint(f[0], 10, 64); err != nil {
					return nil, err
				}
			}
		case "VmStk":
			{
				f := strings.Fields(v)
				if status.VmStk, err = strconv.ParseUint(f[0], 10, 64); err != nil {
					return nil, err
				}
			}
		case "VmExe":
			{
				f := strings.Fields(v)
				if status.VmExe, err = strconv.ParseUint(f[0], 10, 64); err != nil {
					return nil, err
				}
			}
		case "VmLib":
			{
				f := strings.Fields(v)
				if status.VmLib, err = strconv.ParseUint(f[0], 10, 64); err != nil {
					return nil, err
				}
			}
		case "VmPTE":
			{
				f := strings.Fields(v)
				if status.VmPTE, err = strconv.ParseUint(f[0], 10, 64); err != nil {
					return nil, err
				}
			}
		case "VmSwap":
			{
				f := strings.Fields(v)
				if status.VmSwap, err = strconv.ParseUint(f[0], 10, 64); err != nil {
					return nil, err
				}
			}
		case "Threads":
			if status.Threads, err = strconv.ParseUint(v, 10, 64); err != nil {
				return nil, err
			}
		case "SigQ":
			{
				if f := strings.Split(v, "/"); len(f) == 2 {
					if status.SigQLength, err = strconv.ParseUint(f[0], 10, 64); err != nil {
						return nil, err
					}
					if status.SigQLimit, err = strconv.ParseUint(f[1], 10, 64); err != nil {
						return nil, err
					}
				}
			}
		case "SigPnd":
			if status.SigPnd, err = strconv.ParseUint(v, 16, 64); err != nil {
				return nil, err
			}
		case "ShdPnd":
			if status.ShdPnd, err = strconv.ParseUint(v, 16, 64); err != nil {
				return nil, err
			}
		case "SigBlk":
			if status.SigBlk, err = strconv.ParseUint(v, 16, 64); err != nil {
				return nil, err
			}
		case "SigIgn":
			if status.SigIgn, err = strconv.ParseUint(v, 16, 64); err != nil {
				return nil, err
			}
		case "SigCgt":
			if status.SigCgt, err = strconv.ParseUint(v, 16, 64); err != nil {
				return nil, err
			}
		case "CapInh":
			if status.CapInh, err = strconv.ParseUint(v, 16, 64); err != nil {
				return nil, err
			}
		case "CapPrm":
			if status.CapPrm, err = strconv.ParseUint(v, 16, 64); err != nil {
				return nil, err
			}
		case "CapEff":
			if status.CapEff, err = strconv.ParseUint(v, 16, 64); err != nil {
				return nil, err
			}
		case "CapBnd":
			if status.CapBnd, err = strconv.ParseUint(v, 16, 64); err != nil {
				return nil, err
			}
		case "Seccomp":
			{

				var n uint64

				if n, err = strconv.ParseUint(v, 10, 8); err != nil {
					return nil, err
				}

				status.Seccomp = uint8(n)
			}
		case "Cpus_allowed":
			{

				var n uint64

				f := strings.Split(v, ",")
				status.CpusAllowed = make([]uint32, len(f))

				for i := range status.CpusAllowed {
					if n, err = strconv.ParseUint(f[i], 16, 32); err != nil {
						return nil, err
					}
					status.CpusAllowed[i] = uint32(n)
				}

			}
		case "Mems_allowed":
			{

				var n uint64

				f := strings.Split(v, ",")
				status.MemsAllowed = make([]uint32, len(f))

				for i := range status.MemsAllowed {
					if n, err = strconv.ParseUint(f[i], 16, 32); err != nil {
						return nil, err
					}
					status.MemsAllowed[i] = uint32(n)
				}

			}
		case "voluntary_ctxt_switches":
			if status.VoluntaryCtxtSwitches, err = strconv.ParseUint(v, 10, 64); err != nil {
				return nil, err
			}
		case "nonvoluntary_ctxt_switches":
			if status.NonvoluntaryCtxtSwitches, err = strconv.ParseUint(v, 10, 64); err != nil {
				return nil, err
			}
		}
	}

	return &status, nil
}
