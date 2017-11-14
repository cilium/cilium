package linux

import (
	"errors"
	"io/ioutil"
	"strconv"
	"strings"
)

type LoadAvg struct {
	Last1Min       float64 `json:"last1min"`
	Last5Min       float64 `json:"last5min"`
	Last15Min      float64 `json:"last15min"`
	ProcessRunning uint64  `json:"process_running"`
	ProcessTotal   uint64  `json:"process_total"`
	LastPID        uint64  `json:"last_pid"`
}

func ReadLoadAvg(path string) (*LoadAvg, error) {

	b, err := ioutil.ReadFile(path)

	if err != nil {
		return nil, err
	}

	content := strings.TrimSpace(string(b))
	fields := strings.Fields(content)

	if len(fields) < 5 {
		return nil, errors.New("Cannot parse loadavg: " + content)
	}

	process := strings.Split(fields[3], "/")

	if len(process) != 2 {
		return nil, errors.New("Cannot parse loadavg: " + content)
	}

	loadavg := LoadAvg{}

	if loadavg.Last1Min, err = strconv.ParseFloat(fields[0], 64); err != nil {
		return nil, err
	}

	if loadavg.Last5Min, err = strconv.ParseFloat(fields[1], 64); err != nil {
		return nil, err
	}

	if loadavg.Last15Min, err = strconv.ParseFloat(fields[2], 64); err != nil {
		return nil, err
	}

	if loadavg.ProcessRunning, err = strconv.ParseUint(process[0], 10, 64); err != nil {
		return nil, err
	}

	if loadavg.ProcessTotal, err = strconv.ParseUint(process[1], 10, 64); err != nil {
		return nil, err
	}

	if loadavg.LastPID, err = strconv.ParseUint(fields[4], 10, 64); err != nil {
		return nil, err
	}

	return &loadavg, nil
}
