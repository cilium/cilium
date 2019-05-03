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

// +build linux

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

#define READ_ONCE(x)		(*(volatile typeof(x) *)&x)
#define WRITE_ONCE(x, v)	(*(volatile typeof(x) *)&x) = (v)

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

#if defined(__x86_64__)
# define barrier()				\
	asm volatile("" ::: "memory")

# define smp_store_release(p, v)		\
do {						\
	barrier();				\
	WRITE_ONCE(*p, v);			\
} while (0)

# define smp_load_acquire(p)			\
({						\
	typeof(*p) ___p1 = READ_ONCE(*p);	\
	barrier();				\
	___p1;					\
})

static inline uint64_t perf_read_head(struct perf_event_mmap_page *up)
{
	return smp_load_acquire(&up->data_head);
}

static inline void perf_write_tail(struct perf_event_mmap_page *up,
				   uint64_t data_tail)
{
	smp_store_release(&up->data_tail, data_tail);
}
#else
# define smp_mb()	__sync_synchronize()
# define smp_rmb()	__sync_synchronize()

static inline uint64_t perf_read_head(struct perf_event_mmap_page *up)
{
	uint64_t data_head = READ_ONCE(up->data_head);

	smp_rmb();
	return data_head;
}

static inline void perf_write_tail(struct perf_event_mmap_page *up,
				   uint64_t data_tail)
{
	smp_mb();
	WRITE_ONCE(up->data_tail, data_tail);
}
#endif

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
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"reflect"
	"runtime"
	"time"
	"unsafe"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/spanstat"

	"golang.org/x/sys/unix"
)

const (
	MAX_POLL_EVENTS = 32
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

	var duration *spanstat.SpanStat
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		duration = spanstat.Start()
	}
	ret, _, err := unix.Syscall6(
		unix.SYS_PERF_EVENT_OPEN,
		uintptr(unsafe.Pointer(&attr)),
		uintptr(pid),
		uintptr(cpu),
		uintptr(groupFD),
		uintptr(flags), 0)
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpPerfEventOpen, metrics.Errno2Outcome(err)).Observe(duration.EndError(err).Total().Seconds())
	}

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

// allocateBuffers initializes the buffers for sharing between Golang and C.
func (e *PerfEvent) allocateBuffers() {
	// C.malloc() will crash the program if allocation fails, skip check:
	// https://golang.org/cmd/cgo/
	e.state = C.malloc(C.size_t(unsafe.Sizeof(C.struct_read_state{})))
	e.buf = C.malloc(C.size_t(e.pagesize))
}

func (e *PerfEvent) freeBuffers() {
	C.free(e.buf)
	C.free(e.state)
}

func (e *PerfEvent) Enable() error {
	e.allocateBuffers()
	var duration *spanstat.SpanStat
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		duration = spanstat.Start()
	}
	err := unix.IoctlSetInt(e.Fd, unix.PERF_EVENT_IOC_ENABLE, 0)
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpPerfEventEnable, metrics.Error2Outcome(err)).Observe(duration.EndError(err).Total().Seconds())
	}
	if err != nil {
		e.freeBuffers()
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
	var duration *spanstat.SpanStat
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		duration = spanstat.Start()
	}
	err := unix.IoctlSetInt(e.Fd, unix.PERF_EVENT_IOC_DISABLE, 0)
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpPerfEventDisable, metrics.Error2Outcome(err)).Observe(duration.EndError(err).Total().Seconds())
	}
	if err != nil {
		ret = fmt.Errorf("Unable to disable perf event: %v", err)
	}

	e.freeBuffers()
	return ret
}

// Read attempts to read all events from the perf event buffer, calling one of
// the receive / lost functions for each event. receiveFn is called when the
// event is a valid sample; lostFn is called when the kernel has attempted to
// write an event into the ringbuffer but ran out of space for the event.
//
// If all events are not read within a time period (default 20s), it will call
// errFn() and stop reading events.
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

		// Storing the C pointer to the temporary wrapper buffer on the
		// stack allows CGo to understand it better when passing into
		// perf_event_read(), to avoid the following error:
		//
		// runtime error: cgo argument has Go pointer to Go pointer
		//
		// We MUST store it back to 'e' in case it was reallocated.
		wrapBuf := e.buf
		if ok = C.perf_event_read(C.int(e.pagesize),
			unsafe.Pointer(&e.data[0]), unsafe.Pointer(e.state),
			unsafe.Pointer(&wrapBuf), unsafe.Pointer(&msg),
			unsafe.Pointer(&sample), unsafe.Pointer(&lost)); ok == 0 {
			e.buf = wrapBuf
			break
		}
		e.buf = wrapBuf

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

func (e *EventMap) Update(fd int, ubaPtr, sizeOf uintptr) error {
	return UpdateElementFromPointers(e.fd, ubaPtr, sizeOf)
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

	uba := bpfAttrMapOpElem{
		mapFd: uint32(e.eventMap.fd),
		flags: uint64(0),
	}
	ubaPtr := uintptr(unsafe.Pointer(&uba))
	ubaSizeOf := unsafe.Sizeof(uba)

	for _, event := range e.event {
		// FIXME: Not sure what to do here, the map has already been updated and we can't
		// fully restore it.
		uba.key = uint64(uintptr(unsafe.Pointer(&event.cpu)))
		uba.value = uint64(uintptr(unsafe.Pointer(&event.Fd)))
		if err := e.eventMap.Update(e.eventMap.fd, ubaPtr, ubaSizeOf); err != nil {
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

// decode uses reflection to read bytes directly from 'reader' into the object
// pointed to from 'i'. Assumes that 'i' is a pointer.
//
// This function should not be used from performance-sensitive code.
func decode(i interface{}, reader io.ReadSeeker) error {
	value := reflect.ValueOf(i).Elem()
	decodeSize := int64(reflect.TypeOf(value).Size())
	if _, err := reader.Seek(decodeSize, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek into reader %d bytes", decodeSize)
	}
	_, _ = reader.Seek(0, io.SeekStart)

	for i := 0; i < value.NumField(); i++ {
		if err := binary.Read(reader, binary.LittleEndian, value.Field(i).Addr().Interface()); err != nil {
			return fmt.Errorf("failed to decode field %d", i)
		}
	}
	return nil
}

// ReadState is a golang reflection of C.struct_read_state{}
type ReadState struct {
	Base     uint64 // Actually a pointer
	RawSize  uint64
	LastSize uint64
}

// Decode populates 'r' based on the bytes read from the specified reader.
//
// This function should not be used from performance-sensitive code.
func (r *ReadState) Decode(reader io.ReadSeeker) error {
	return decode(r, reader)
}

// PerfEventMmapPage reflects the Linux 'struct perf_event_mmap_page'
type PerfEventMmapPage struct {
	Version       uint32 // version number of this structure
	CompatVersion uint32 // lowest version this is compat with

	Lock        uint32 // seqlock for synchronization
	Index       uint32 // hardware event identifier
	Offset      int64  // add to hardware event value
	TimeEnabled uint64 // time event active
	TimeRunning uint64 // time event on cpu
	//union {
	Capabilities uint64
	//struct {
	//	__u64	cap_bit0		: 1, /* Always 0, deprecated, see commit 860f085b74e9 */
	//		cap_bit0_is_deprecated	: 1, /* Always 1, signals that bit 0 is zero */

	//		cap_user_rdpmc		: 1, /* The RDPMC instruction can be used to read counts */
	//		cap_user_time		: 1, /* The time_* fields are used */
	//		cap_user_time_zero	: 1, /* The time_zero field is used */
	//		cap_____res		: 59;
	//};
	//};
	PmcWidth uint16

	TimeShift  uint16
	TimeMult   uint32
	TimeOffset uint64
	TimeZero   uint64
	Size       uint32

	Reserved [118*8 + 4]uint8 // align to 1k.

	DataHead   uint64 // head in the data section
	DataTail   uint64 // user-space written tail
	DataOffset uint64 // where the buffer starts
	DataSize   uint64 // data buffer size

	AuxHead   uint64
	AuxTail   uint64
	AuxOffset uint64
	AuxSize   uint64
}

// Decode populates 'p' base on the bytes read from the specified reader.
//
// This function should not be used from performance-sensitive code.
func (p *PerfEventMmapPage) Decode(reader io.ReadSeeker) error {
	return decode(p, reader)
}

// PerfEventFromMemory creates an in-memory PerfEvent object for testing
// and analysis purposes. No kernel interaction is made.
//
// The caller MUST eventually call Disable() to free event resources.
func PerfEventFromMemory(page *PerfEventMmapPage, buf []byte) *PerfEvent {
	pagesize := os.Getpagesize()
	e := &PerfEvent{
		cpu:      1,
		pagesize: pagesize,
		npages:   int(page.DataSize) / pagesize,
		data:     buf,
	}

	e.allocateBuffers()
	return e
}
