package linux

import (
	"io/ioutil"
	"strconv"
	"strings"
	"time"
)

type Uptime struct {
	Total float64 `json:"total"`
	Idle  float64 `json:"idle"`
}

func (self *Uptime) GetTotalDuration() time.Duration {
	return time.Duration(self.Total) * time.Second
}

func (self *Uptime) GetIdleDuration() time.Duration {
	return time.Duration(self.Idle) * time.Second
}

func (self *Uptime) CalculateIdle() float64 {
	// XXX
	// num2/(num1*N)     # N = SMP CPU numbers
	return 0
}

func ReadUptime(path string) (*Uptime, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	fields := strings.Fields(string(b))
	uptime := Uptime{}
	if uptime.Total, err = strconv.ParseFloat(fields[0], 64); err != nil {
		return nil, err
	}
	if uptime.Idle, err = strconv.ParseFloat(fields[1], 64); err != nil {
		return nil, err
	}
	return &uptime, nil
}
