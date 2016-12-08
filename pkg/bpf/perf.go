//
// Copyright 2016 Authors of Cilium
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
//
package bpf

/*
#cgo CFLAGS: -I../../bpf/include
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <linux/unistd.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <sys/resource.h>

void create_perf_event_attr(int type, int config, int sample_type,
			    int wakeup_events, void *attr)
{
	struct perf_event_attr *ptr = (struct perf_event_attr *) attr;

	memset(ptr, 0, sizeof(*ptr));

	ptr->type = type;
	ptr->config = config;
	ptr->sample_type = sample_type;
	ptr->wakeup_events = wakeup_events;

}

struct event_sample {
	struct perf_event_header header;
	uint32_t size;
	uint8_t data[];
};

struct read_state {
	void *buf;
	int buf_len;
};

int perf_event_read(int page_count, int page_size, void *_state,
		    void *_header, void *_sample_ptr, void *_lost_ptr)
{
	volatile struct perf_event_mmap_page *header = _header;
	uint64_t data_head = *((volatile uint64_t *) &header->data_head);
	uint64_t data_tail = header->data_tail;
	uint64_t raw_size = (uint64_t)page_count * page_size;
	void *base  = ((uint8_t *)header) + page_size;
	struct read_state *state = _state;
	struct event_sample *e;
	void *begin, *end;
	void **sample_ptr = (void **) _sample_ptr;
	void **lost_ptr = (void **) _lost_ptr;

	// No data to read on this ring
	__sync_synchronize();
	if (data_head == data_tail)
		return 0;

	begin = base + data_tail % raw_size;
	e = begin;
	end = base + (data_tail + e->header.size) % raw_size;

	if (state->buf_len < e->header.size || !state->buf) {
		state->buf = realloc(state->buf, e->header.size);
		state->buf_len = e->header.size;
	}

	if (end < begin) {
		uint64_t len = base + raw_size - begin;

		memcpy(state->buf, begin, len);
		memcpy((char *) state->buf + len, base, e->header.size - len);

		e = state->buf;
	} else {
		memcpy(state->buf, begin, e->header.size);
	}

	switch (e->header.type) {
	case PERF_RECORD_SAMPLE:
		*sample_ptr = state->buf;
		break;
	case PERF_RECORD_LOST:
		*lost_ptr = state->buf;
		break;
	}

	__sync_synchronize();
	header->data_tail += e->header.size;

	return e->header.type;
}

*/
import "C"

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	MAX_POLL_EVENTS = 32
)

type PerfEventConfig struct {
	NumCpus      int
	NumPages     int
	MapPath      string
	Type         int
	Config       int
	SampleType   int
	WakeupEvents int
}

func DefaultPerfEventConfig() *PerfEventConfig {
	return &PerfEventConfig{
		MapPath:      "/sys/fs/bpf/tc/globals/cilium_events",
		Type:         C.PERF_TYPE_SOFTWARE,
		Config:       C.PERF_COUNT_SW_BPF_OUTPUT,
		SampleType:   C.PERF_SAMPLE_RAW,
		WakeupEvents: 0,
		NumCpus:      runtime.NumCPU(),
		NumPages:     8,
	}
}

type PerfEvent struct {
	cpu      int
	Fd       int
	pagesize int
	npages   int
	lost     uint64
	unknown  uint64
	data     []byte
}

// Matching 'struct perf_event_header in <linux/perf_event.h>
type PerfEventHeader struct {
	Type      uint32
	Misc      uint16
	TotalSize uint16
}

// Matching 'struct perf_event_sample in kernel sources
type PerfEventSample struct {
	PerfEventHeader
	Size uint32
	data byte // Size bytes of data
}

// Matching 'struct perf_event_lost in kernel sources
type PerfEventLost struct {
	PerfEventHeader
	Id   uint64
	Lost uint64
}

func (e *PerfEventSample) DataDirect() []byte {
	// http://stackoverflow.com/questions/27532523/how-to-convert-1024c-char-to-1024byte
	size := e.Size - 4
	return (*[1 << 30]byte)(unsafe.Pointer(&e.data))[:int(size):int(size)]
}

func (e *PerfEventSample) DataCopy() []byte {
	return C.GoBytes(unsafe.Pointer(&e.data), C.int(e.Size))
}

type ReceiveFunc func(msg *PerfEventSample, cpu int)
type LostFunc func(msg *PerfEventLost, cpu int)

func PerfEventOpen(config *PerfEventConfig, pid int, cpu int, groupFD int, flags int) (*PerfEvent, error) {
	attr := C.struct_perf_event_attr{}

	C.create_perf_event_attr(
		C.int(config.Type),
		C.int(config.Config),
		C.int(config.SampleType),
		C.int(config.WakeupEvents),
		unsafe.Pointer(&attr),
	)

	ret, _, err := syscall.Syscall6(
		C.__NR_perf_event_open,
		uintptr(unsafe.Pointer(&attr)),
		uintptr(pid),
		uintptr(cpu),
		uintptr(groupFD),
		uintptr(flags), 0)

	if int(ret) > 0 && err == 0 {
		return &PerfEvent{
			cpu: cpu,
			Fd:  int(ret),
		}, nil
	}
	return nil, fmt.Errorf("Unable to open perf event: %s", err)
}

func (e *PerfEvent) Mmap(pagesize int, npages int) error {
	size := pagesize * (npages + 1)
	data, err := syscall.Mmap(e.Fd,
		0,
		size,
		syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED)

	if err != nil {
		return fmt.Errorf("Unable to mmap perf event: %s", err)
	}

	e.pagesize = pagesize
	e.npages = npages
	e.data = data

	return nil
}

func (e *PerfEvent) Enable() error {
	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(e.Fd),
		C.PERF_EVENT_IOC_ENABLE,
		0)

	if err != 0 {
		return fmt.Errorf("Unable to enable perf event: %s", err)
	}

	return nil
}

func (e *PerfEvent) Disable() error {
	if e == nil {
		return nil
	}

	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(e.Fd),
		C.PERF_EVENT_IOC_DISABLE,
		0)

	if err != 0 {
		return fmt.Errorf("Unable to disable perf event: %s", err)
	}

	return nil
}

func (e *PerfEvent) Read(receive ReceiveFunc, lostFn LostFunc) error {
	state := C.struct_read_state{}

	for {
		var sample *PerfEventSample
		var lost *PerfEventLost

		ok := C.perf_event_read(C.int(e.npages), C.int(e.pagesize),
			unsafe.Pointer(&state), unsafe.Pointer(&e.data[0]),
			unsafe.Pointer(&sample), unsafe.Pointer(&lost))

		switch ok {
		case 0:
			return nil
		case C.PERF_RECORD_SAMPLE:
			receive(sample, e.cpu)
		case C.PERF_RECORD_LOST:
			e.lost += lost.Lost
			if lostFn != nil {
				lostFn(lost, e.cpu)
			}
		default:
			e.unknown++
		}
	}
}

func (e *PerfEvent) Close() {
	if e == nil {
		return
	}

	syscall.Close(e.Fd)
}

type EPoll struct {
	fd     int
	nfds   int
	events [MAX_POLL_EVENTS]syscall.EpollEvent
}

func (ep *EPoll) AddFD(fd int, events uint32) error {
	ev := syscall.EpollEvent{
		Events: events,
		Fd:     int32(fd),
	}

	return syscall.EpollCtl(ep.fd, syscall.EPOLL_CTL_ADD, fd, &ev)
}

func (ep *EPoll) Poll(timeout int) (int, error) {
	nfds, err := syscall.EpollWait(ep.fd, ep.events[0:], timeout)
	if err != nil {
		return 0, err
	}

	ep.nfds = nfds

	return nfds, nil
}

func (ep *EPoll) Close() {
	if ep.fd > 0 {
		syscall.Close(ep.fd)
	}
}

type EventMap struct {
	fd int
}

func openMap(path string) (*EventMap, error) {
	fd, err := ObjGet(path)
	if err != nil {
		return nil, err
	}

	return &EventMap{
		fd: fd,
	}, nil
}

func (e *EventMap) Update(ev *PerfEvent) error {
	return UpdateElement(e.fd, unsafe.Pointer(&ev.cpu), unsafe.Pointer(&ev.Fd), 0)
}

func (e *EventMap) Close() {
	if e == nil {
		return
	}

	syscall.Close(e.fd)
}

type PerCpuEvents struct {
	cpus     int
	npages   int
	pagesize int
	eventMap *EventMap
	event    map[int]*PerfEvent
	poll     EPoll
}

func NewPerCpuEvents(config *PerfEventConfig) (*PerCpuEvents, error) {
	var err error

	e := &PerCpuEvents{
		cpus:     config.NumCpus,
		npages:   config.NumPages,
		pagesize: os.Getpagesize(),
		event:    make(map[int]*PerfEvent),
	}

	defer func() {
		if err != nil {
			e.CloseAll()
		}
	}()

	e.poll.fd, err = syscall.EpollCreate1(0)
	if err != nil {
		return nil, err
	}

	e.eventMap, err = openMap(config.MapPath)
	if err != nil {
		return nil, err
	}

	for cpu := int(0); cpu < config.NumCpus; cpu++ {
		event, err := PerfEventOpen(config, -1, cpu, -1, 0)
		if err != nil {
			return nil, err
		} else {
			e.event[event.Fd] = event
		}

		if err := e.poll.AddFD(event.Fd, syscall.EPOLLIN); err != nil {
			return nil, err
		}

		if err = event.Mmap(e.pagesize, e.npages); err != nil {
			return nil, err
		}

		if err = event.Enable(); err != nil {
			return nil, err
		}
	}

	for _, event := range e.event {
		// FIXME: Not sure what to do here, the map has already been updated and we can't
		// fully restore it.
		if err := e.eventMap.Update(event); err != nil {
			return nil, err
		}
	}

	return e, nil
}

func (e *PerCpuEvents) Poll(timeout int) (int, error) {
	return e.poll.Poll(timeout)
}

func (e *PerCpuEvents) ReadAll(receive ReceiveFunc, lost LostFunc) error {
	for i := 0; i < e.poll.nfds; i++ {
		fd := int(e.poll.events[i].Fd)
		if event, ok := e.event[fd]; ok {
			if err := event.Read(receive, lost); err != nil {
				return err
			}
		}
	}

	return nil
}

func (e *PerCpuEvents) Stats() (uint64, uint64) {
	var lost, unknown uint64

	for _, event := range e.event {
		lost += event.lost
		unknown += event.unknown
	}

	return lost, unknown
}

func (e *PerCpuEvents) CloseAll() error {
	var retErr error

	e.eventMap.Close()
	e.poll.Close()

	for _, event := range e.event {
		if err := event.Disable(); err != nil {
			retErr = err
		}

		event.Close()
	}

	return retErr
}
