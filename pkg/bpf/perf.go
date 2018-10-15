// Copyright 2016-2018 Authors of Cilium
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
#include <stdlib.h>

// Only x64 and arm64 right now, but trivial to extend.
#if defined(__x86_64__)
# define mb()           asm volatile("mfence" ::: "memory")
# define rmb()          asm volatile("lfence" ::: "memory")
#elif defined(__aarch64__)
# define mb()           asm volatile("dmb ish" ::: "memory")
# define rmb()          asm volatile("dmb ishld" ::: "memory")
#else
# error "Please define mb(), rmb() barriers!"
#endif

#define READ_ONCE_64(x)	*((volatile uint64_t *) &x)

void create_perf_event_attr(int type, int config, int sample_type,
			    int wakeup_events, void *attr)
{
	struct perf_event_attr *ptr = attr;

	memset(ptr, 0, sizeof(*ptr));

	ptr->type = type;
	ptr->config = config;
	ptr->sample_type = sample_type;
	ptr->sample_period = 1;
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
	void *base;
	uint64_t raw_size;
	uint64_t last_size;
};

// Contract with kernel/user space on perf ring buffer. From
// kernel/events/ring_buffer.c:
//
//   kernel                             user
//
//   if (LOAD ->data_tail) {            LOAD ->data_head
//                      (A)             smp_rmb()       (C)
//      STORE $data                     LOAD $data
//      smp_wmb()       (B)             smp_mb()        (D)
//      STORE ->data_head               STORE ->data_tail
//   }
//
// Where A pairs with D, and B pairs with C.
//
// In our case (A) is a control dependency that separates the load
// of the ->data_tail and the stores of $data. In case ->data_tail
// indicates there is no room in the buffer to store $data we do
// not. D needs to be a full barrier since it separates the data
// READ from the tail WRITE. For B a WMB is sufficient since it
// separates two WRITEs, and for C an RMB is sufficient since it
// separates two READs.

static inline uint64_t perf_read_head(struct perf_event_mmap_page *up)
{
	uint64_t data_head = READ_ONCE_64(up->data_head);
	rmb();
	return data_head;
}

static inline void perf_write_tail(struct perf_event_mmap_page *up,
				   uint64_t data_tail)
{
	mb();
	up->data_tail = data_tail;
}

void perf_event_reset_tail(void *_page)
{
	struct perf_event_mmap_page *up = _page;
	uint64_t data_head = perf_read_head(up);

	// Reset tail to good known state aka tell kernel we've
	// consumed all data.
	perf_write_tail(up, data_head);
}

int perf_event_read_init(int page_count, int page_size, void *_page,
			 void *_state)
{
	struct perf_event_mmap_page *up = _page;
	struct read_state *state = _state;
	uint64_t data_tail = up->data_tail;

	if (perf_read_head(up) == data_tail)
		return 0;

	state->raw_size = page_count * page_size;
	state->base = ((uint8_t *)up) + page_size;
	state->last_size = 0;

	return 1;
}

int perf_event_read(int page_size, void *_page, void *_state,
		    void *_buf, void *_msg, void *_sample, void *_lost)
{
	struct perf_event_mmap_page *up = _page;
	struct read_state *state = _state;
	void **sample = (void **) _sample;
	void **lost = (void **) _lost;
	void **msg = (void **) _msg;
	void **buf = (void **) _buf;
	uint64_t e_size, data_tail;
	struct event_sample *e;
	int trunc = 0;
	void *begin;

	data_tail = up->data_tail + state->last_size;
	perf_write_tail(up, data_tail);
	if (perf_read_head(up) == data_tail)
		return 0;

	// raw_size is guaranteed power of 2
	e = begin = state->base + (data_tail & (state->raw_size - 1));
	e_size = state->last_size = e->header.size;
	if (begin + e_size > state->base + state->raw_size) {
		uint64_t len = state->base + state->raw_size - begin;
		uint64_t len_first, len_secnd;
		void *ptr = *buf;

		// For small sizes, we just go with prealloc'ed buffer.
		if (e_size > page_size) {
			ptr = realloc(*buf, e_size);
			if (!ptr) {
				ptr = *buf;
				trunc = 1;
			} else {
				*buf = ptr;
			}
		}

		len_first = trunc ? (len <= page_size ? len : page_size) : len;
		memcpy(ptr, begin, len_first);
		len_secnd = trunc ? (page_size - len_first) : e_size - len;
		memcpy(ptr + len_first, state->base, len_secnd);
		e = ptr;
	}

	*msg = e;
	if (e->header.type == PERF_RECORD_SAMPLE) {
		*sample = e;
	} else if (e->header.type == PERF_RECORD_LOST) {
		*lost = e;
	}

	return 1 + trunc;
}
*/
import "C"

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
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
	trunc    uint64
	unknown  uint64
	data     []byte
	// state is placed here to reduce memory allocations
	state unsafe.Pointer
	// buf is placed here to reduce memory allocations
	buf unsafe.Pointer
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
	return (*[1 << 30]byte)(unsafe.Pointer(&e.data))[:int(e.Size):int(e.Size)]
}

func (e *PerfEventSample) DataCopy() []byte {
	return C.GoBytes(unsafe.Pointer(&e.data), C.int(e.Size))
}

type ReceiveFunc func(msg *PerfEventSample, cpu int)
type LostFunc func(msg *PerfEventLost, cpu int)

// ErrorFunc is run when reading PerfEvent results in an error
type ErrorFunc func(msg *PerfEvent)

func PerfEventOpen(config *PerfEventConfig, pid int, cpu int, groupFD int, flags int) (*PerfEvent, error) {
	attr := C.struct_perf_event_attr{}

	C.create_perf_event_attr(
		C.int(config.Type),
		C.int(config.Config),
		C.int(config.SampleType),
		C.int(config.WakeupEvents),
		unsafe.Pointer(&attr),
	)

	ret, _, err := unix.Syscall6(
		unix.SYS_PERF_EVENT_OPEN,
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
	datasize := uint32(pagesize) * uint32(npages)
	if (datasize & (datasize - 1)) != 0 {
		return fmt.Errorf("Unable to mmap perf event: ring size not power of 2")
	}

	size := pagesize * (npages + 1)
	data, err := unix.Mmap(e.Fd,
		0,
		size,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("Unable to mmap perf event: %s", err)
	}

	e.pagesize = pagesize
	e.npages = npages
	e.data = data

	return nil
}

func (e *PerfEvent) Munmap() error {
	return unix.Munmap(e.data)
}

func (e *PerfEvent) Enable() error {
	e.state = C.malloc(C.size_t(unsafe.Sizeof(C.struct_read_state{})))
	if e.state == nil {
		return fmt.Errorf("Unable to enable perf event: cannot allocate buffers")
	}

	e.buf = C.malloc(C.size_t(e.pagesize))
	if e.buf == nil {
		C.free(e.state)
		return fmt.Errorf("Unable to enable perf event: cannot allocate buffers")
	}

	if err := unix.IoctlSetInt(e.Fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		C.free(e.state)
		C.free(e.buf)
		return fmt.Errorf("Unable to enable perf event: %v", err)
	}

	return nil
}

func (e *PerfEvent) Disable() error {
	var ret error

	if e == nil {
		return nil
	}

	// Does not fail in perf's kernel-side ioctl handler, but even if
	// there's not much we can do here ...
	ret = nil
	if err := unix.IoctlSetInt(e.Fd, unix.PERF_EVENT_IOC_DISABLE, 0); err != nil {
		ret = fmt.Errorf("Unable to disable perf event: %v", err)
	}

	C.free(e.buf)
	C.free(e.state)
	return ret
}

func (e *PerfEvent) Read(receive ReceiveFunc, lostFn LostFunc, err ErrorFunc) {
	// Prepare for reading and check if events are available
	available := C.perf_event_read_init(C.int(e.npages), C.int(e.pagesize),
		unsafe.Pointer(&e.data[0]), unsafe.Pointer(e.state))

	// Poll false positive
	if available == 0 {
		return
	}

	timer := time.After(20 * time.Second)

read:
	for {
		var (
			msg    *PerfEventHeader
			sample *PerfEventSample
			lost   *PerfEventLost
			ok     C.int
		)

		if ok = C.perf_event_read(C.int(e.pagesize),
			unsafe.Pointer(&e.data[0]), unsafe.Pointer(e.state),
			unsafe.Pointer(&e.buf), unsafe.Pointer(&msg),
			unsafe.Pointer(&sample), unsafe.Pointer(&lost)); ok == 0 {
			break
		}

		if ok == 2 {
			e.trunc++
		}
		if msg.Type == C.PERF_RECORD_SAMPLE {
			receive(sample, e.cpu)
		} else if msg.Type == C.PERF_RECORD_LOST {
			e.lost += lost.Lost
			if lostFn != nil {
				lostFn(lost, e.cpu)
			}
		} else {
			e.unknown++
		}

		select {
		case <-timer:
			err(e)
			C.perf_event_reset_tail(unsafe.Pointer(&e.data[0]))
			break read
		default:
		}
	}
}

func (e *PerfEvent) Close() {
	if e == nil {
		return
	}

	unix.Close(e.Fd)
}

// Debug returns string with internal information about PerfEvent
func (e *PerfEvent) Debug() string {
	return fmt.Sprintf("cpu: %d, Fd: %d, pagesize: %d, npages: %d, lost: %d, unknown: %d, state: %v", e.cpu, e.Fd, e.pagesize, e.npages, e.lost, e.unknown, C.GoBytes(e.state, C.sizeof_struct_read_state))
}

func (e *PerfEvent) DebugDump() string {
	return fmt.Sprintf("%s, data: %v", e.Debug(), e.data)
}

type EPoll struct {
	fd     int
	nfds   int
	events [MAX_POLL_EVENTS]unix.EpollEvent
}

func (ep *EPoll) AddFD(fd int, events uint32) error {
	ev := unix.EpollEvent{
		Events: events,
		Fd:     int32(fd),
	}

	return unix.EpollCtl(ep.fd, unix.EPOLL_CTL_ADD, fd, &ev)
}

func (ep *EPoll) Poll(timeout int) (int, error) {
	nfds, err := unix.EpollWait(ep.fd, ep.events[0:], timeout)
	if err != nil {
		return 0, err
	}

	ep.nfds = nfds

	return nfds, nil
}

func (ep *EPoll) Close() {
	if ep.fd > 0 {
		unix.Close(ep.fd)
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

	unix.Close(e.fd)
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

	e.poll.fd, err = unix.EpollCreate1(0)
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

		if err = e.poll.AddFD(event.Fd, unix.EPOLLIN); err != nil {
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

// ReadAll reads perf events
func (e *PerCpuEvents) ReadAll(receive ReceiveFunc, lost LostFunc, handleError ErrorFunc) error {
	for i := 0; i < e.poll.nfds; i++ {
		fd := int(e.poll.events[i].Fd)
		if event, ok := e.event[fd]; ok {
			event.Read(receive, lost, handleError)
		}
	}

	return nil
}

func (e *PerCpuEvents) Stats() (uint64, uint64, uint64) {
	var lost, trunc, unknown uint64

	for _, event := range e.event {
		lost += event.lost
		trunc += event.trunc
		unknown += event.unknown
	}

	return lost, trunc, unknown
}

func (e *PerCpuEvents) CloseAll() error {
	var retErr error

	e.eventMap.Close()
	e.poll.Close()

	for _, event := range e.event {
		if err := event.Disable(); err != nil {
			retErr = err
		}

		event.Munmap()
		event.Close()
	}

	return retErr
}
