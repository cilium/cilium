// Copyright 2016-2017 Authors of Cilium
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

package bpf

/*
#cgo CFLAGS: -I../../bpf/include
#include <stdio.h>
#include <string.h>
#include <stdint.h>
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

static void dump_data(uint8_t *data, size_t size, int cpu)
{
	int i;

	printf("event on cpu%d: ", cpu);
	for (i = 0; i < size; i++)
		printf("%02x ", data[i]);
	printf("\n");
}

struct event_sample {
	struct perf_event_header header;
	uint32_t size;
	uint8_t data[];
};

struct read_state {
	size_t raw_size;
	void *base, *begin, *end, *head;
};

int perf_event_read_init(int page_count, int page_size, void *_header, void *_state)
{
	volatile struct perf_event_mmap_page *header = _header;
	struct read_state *state = _state;
	uint64_t data_tail = header->data_tail;
	uint64_t data_head = *((volatile uint64_t *) &header->data_head);

	__sync_synchronize();
	if (data_head == data_tail)
		return 0;

	state->head = (void *) data_head;
	state->raw_size = page_count * page_size;
	state->base  = ((uint8_t *)header) + page_size;
	state->begin = state->base + data_tail % state->raw_size;
	state->end   = state->base + data_head % state->raw_size;

	return state->begin != state->end;
}

int perf_event_read(void *_state, void *buf, void *_msg)
{
	void **msg = (void **) _msg;
	struct read_state *state = _state;
	struct event_sample *e = state->begin;

	if (state->begin == state->end)
		return 0;

	if (state->begin + e->header.size > state->base + state->raw_size) {
		uint64_t len = state->base + state->raw_size - state->begin;

		memcpy(buf, state->begin, len);
		memcpy((char *) buf + len, state->base, e->header.size - len);

		e = buf;
		state->begin = state->base + e->header.size - len;
	} else if (state->begin + e->header.size == state->base + state->raw_size) {
		state->begin = state->base;
	} else {
		state->begin += e->header.size;
	}

	*msg = e;

	return 1;
}

void perf_event_read_finish(void *_header, void *_state)
{
	volatile struct perf_event_mmap_page *header = _header;
	struct read_state *state = _state;

	__sync_synchronize();
	header->data_tail = (uint64_t) state->head;
}

void cast(void *ptr, void *_dst)
{
	void **dst = (void **) _dst;
	*dst = ptr;
}

*/
import "C"

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"syscall"
	"unsafe"
)

const (
	EventsMapName   = "cilium_events"
	MAX_POLL_EVENTS = 32

	PERF_TYPE_HARDWARE   = 0
	PERF_TYPE_SOFTWARE   = 1
	PERF_TYPE_TRACEPOINT = 2
	PERF_TYPE_HW_CACHE   = 3
	PERF_TYPE_RAW        = 4
	PERF_TYPE_BREAKPOINT = 5

	PERF_SAMPLE_IP           = 1 << 0
	PERF_SAMPLE_TID          = 1 << 1
	PERF_SAMPLE_TIME         = 1 << 2
	PERF_SAMPLE_ADDR         = 1 << 3
	PERF_SAMPLE_READ         = 1 << 4
	PERF_SAMPLE_CALLCHAIN    = 1 << 5
	PERF_SAMPLE_ID           = 1 << 6
	PERF_SAMPLE_CPU          = 1 << 7
	PERF_SAMPLE_PERIOD       = 1 << 8
	PERF_SAMPLE_STREAM_ID    = 1 << 9
	PERF_SAMPLE_RAW          = 1 << 10
	PERF_SAMPLE_BRANCH_STACK = 1 << 11
	PERF_SAMPLE_REGS_USER    = 1 << 12
	PERF_SAMPLE_STACK_USER   = 1 << 13
	PERF_SAMPLE_WEIGHT       = 1 << 14
	PERF_SAMPLE_DATA_SRC     = 1 << 15
	PERF_SAMPLE_IDENTIFIER   = 1 << 16
	PERF_SAMPLE_TRANSACTION  = 1 << 17
	PERF_SAMPLE_REGS_INTR    = 1 << 18

	PERF_COUNT_SW_BPF_OUTPUT = 10
)

type PerfEventConfig struct {
	NumCpus      int
	NumPages     int
	MapName      string
	Type         int
	Config       int
	SampleType   int
	WakeupEvents int
}

func DefaultPerfEventConfig() *PerfEventConfig {
	return &PerfEventConfig{
		MapName:      EventsMapName,
		Type:         PERF_TYPE_SOFTWARE,
		Config:       PERF_COUNT_SW_BPF_OUTPUT,
		SampleType:   PERF_SAMPLE_RAW,
		WakeupEvents: 1,
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

// PerfEventHeader must match 'struct perf_event_header in <linux/perf_event.h>.
type PerfEventHeader struct {
	Type      uint32
	Misc      uint16
	TotalSize uint16
}

// PerfEventSample must match 'struct perf_event_sample in kernel sources.
type PerfEventSample struct {
	PerfEventHeader
	Size uint32
	data byte // Size bytes of data
}

// PerfEventLost must match 'struct perf_event_lost in kernel sources.
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
	buf := make([]byte, 256)
	state := C.struct_read_state{}

	// Prepare for reading and check if events are available
	available := C.perf_event_read_init(C.int(e.npages), C.int(e.pagesize),
		unsafe.Pointer(&e.data[0]), unsafe.Pointer(&state))

	// Poll false positive
	if available == 0 {
		return nil
	}

	for {
		var msg *PerfEventHeader

		if ok := C.perf_event_read(unsafe.Pointer(&state),
			unsafe.Pointer(&buf[0]), unsafe.Pointer(&msg)); ok == 0 {
			break
		}

		if msg.Type == C.PERF_RECORD_SAMPLE {
			var sample *PerfEventSample
			C.cast(unsafe.Pointer(msg), unsafe.Pointer(&sample))
			receive(sample, e.cpu)
		} else if msg.Type == C.PERF_RECORD_LOST {
			var lost *PerfEventLost
			C.cast(unsafe.Pointer(msg), unsafe.Pointer(&lost))
			e.lost += lost.Lost
			if lostFn != nil {
				lostFn(lost, e.cpu)
			}
		} else {
			e.unknown++
		}
	}

	// Move ring buffer tail pointer
	C.perf_event_read_finish(unsafe.Pointer(&e.data[0]), unsafe.Pointer(&state))

	return nil
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
	Cpus     int
	Npages   int
	Pagesize int
	eventMap *EventMap
	event    map[int]*PerfEvent
	poll     EPoll
}

func NewPerCpuEvents(config *PerfEventConfig) (*PerCpuEvents, error) {
	var err error

	e := &PerCpuEvents{
		Cpus:     config.NumCpus,
		Npages:   config.NumPages,
		Pagesize: os.Getpagesize(),
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

	mapPath := config.MapName
	if !path.IsAbs(mapPath) {
		mapPath = MapPath(mapPath)
	}

	e.eventMap, err = openMap(mapPath)
	if err != nil {
		return nil, err
	}

	for cpu := int(0); cpu < e.Cpus; cpu++ {
		event, err := PerfEventOpen(config, -1, cpu, -1, 0)
		if err != nil {
			return nil, err
		}
		e.event[event.Fd] = event

		if err := e.poll.AddFD(event.Fd, syscall.EPOLLIN); err != nil {
			return nil, err
		}

		if err = event.Mmap(e.Pagesize, e.Npages); err != nil {
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
