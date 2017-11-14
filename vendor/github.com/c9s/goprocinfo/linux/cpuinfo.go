package linux

import (
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
)

type CPUInfo struct {
	Processors []Processor `json:"processors"`
}

func (self *CPUInfo) NumCPU() int {
	return len(self.Processors)
}

func (self *CPUInfo) NumCore() int {
	core := make(map[string]bool)

	for _, p := range self.Processors {
		pid := p.PhysicalId
		cid := p.CoreId

		if pid == -1 {
			return self.NumCPU()
		} else {
			// to avoid fmt import
			key := strconv.FormatInt(int64(pid), 10) + ":" + strconv.FormatInt(int64(cid), 10)
			core[key] = true
		}
	}

	return len(core)
}

func (self *CPUInfo) NumPhysicalCPU() int {
	pcpu := make(map[string]bool)

	for _, p := range self.Processors {
		pid := p.PhysicalId

		if pid == -1 {
			return self.NumCPU()
		} else {
			// to avoid fmt import
			key := strconv.FormatInt(int64(pid), 10)
			pcpu[key] = true
		}
	}

	return len(pcpu)
}

type Processor struct {
	Id         int64    `json:"id"`
	VendorId   string   `json:"vendor_id"`
	Model      int64    `json:"model"`
	ModelName  string   `json:"model_name"`
	Flags      []string `json:"flags"`
	Cores      int64    `json:"cores"`
	MHz        float64  `json:"mhz"`
	CacheSize  int64    `json:"cache_size"` // KB
	PhysicalId int64    `json:"physical_id"`
	CoreId     int64    `json:"core_id"`
}

var cpuinfoRegExp = regexp.MustCompile("([^:]*?)\\s*:\\s*(.*)$")

func ReadCPUInfo(path string) (*CPUInfo, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	content := string(b)
	lines := strings.Split(content, "\n")

	var cpuinfo = CPUInfo{}
	var processor = &Processor{CoreId: -1, PhysicalId: -1}

	for i, line := range lines {
		var key string
		var value string

		if len(line) == 0 && i != len(lines)-1 {
			// end of processor
			cpuinfo.Processors = append(cpuinfo.Processors, *processor)
			processor = &Processor{}
			continue
		} else if i == len(lines)-1 {
			continue
		}

		submatches := cpuinfoRegExp.FindStringSubmatch(line)
		key = submatches[1]
		value = submatches[2]

		switch key {
		case "processor":
			processor.Id, _ = strconv.ParseInt(value, 10, 64)
		case "vendor_id":
			processor.VendorId = value
		case "model":
			processor.Model, _ = strconv.ParseInt(value, 10, 64)
		case "model name":
			processor.ModelName = value
		case "flags":
			processor.Flags = strings.Fields(value)
		case "cpu cores":
			processor.Cores, _ = strconv.ParseInt(value, 10, 64)
		case "cpu MHz":
			processor.MHz, _ = strconv.ParseFloat(value, 64)
		case "cache size":
			processor.CacheSize, _ = strconv.ParseInt(value[:strings.IndexAny(value, " \t\n")], 10, 64)
			if strings.HasSuffix(line, "MB") {
				processor.CacheSize *= 1024
			}
		case "physical id":
			processor.PhysicalId, _ = strconv.ParseInt(value, 10, 64)
		case "core id":
			processor.CoreId, _ = strconv.ParseInt(value, 10, 64)
		}
		/*
			processor	: 0
			vendor_id	: GenuineIntel
			cpu family	: 6
			model		: 26
			model name	: Intel(R) Xeon(R) CPU           L5520  @ 2.27GHz
		*/
	}
	return &cpuinfo, nil
}
