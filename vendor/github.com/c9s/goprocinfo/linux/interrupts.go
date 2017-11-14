package linux

import (
	"io/ioutil"
	"strconv"
	"strings"
)

type Interrupt struct {
	Name        string
	Counts      []uint64
	Description string
}

type Interrupts struct {
	Interrupts []Interrupt
}

func ReadInterrupts(path string) (*Interrupts, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	content := string(b)
	lines := strings.Split(content, "\n")
	cpus := lines[0]
	lines = append(lines[:0], lines[1:]...)
	numCpus := len(strings.Fields(cpus))
	interrupts := make([]Interrupt, 0)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		counts := make([]uint64, 0)
		i := 0
		for ; i < numCpus; i++ {
			if len(fields) <= i+1 {
				break
			}
			count, err := strconv.ParseInt(fields[i+1], 10, 64)
			if err != nil {
				return nil, err
			}
			counts = append(counts, uint64(count))
		}
		name := strings.TrimSuffix(fields[0], ":")
		description := strings.Join(fields[i+1:], " ")
		interrupts = append(interrupts, Interrupt{
			Name:        name,
			Counts:      counts,
			Description: description,
		})
	}
	return &Interrupts{Interrupts: interrupts}, nil
}
