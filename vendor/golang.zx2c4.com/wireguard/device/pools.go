/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"sync"
	"sync/atomic"
)

type WaitPool struct {
	pool  sync.Pool
	cond  sync.Cond
	lock  sync.Mutex
	count atomic.Uint32
	max   uint32
}

func NewWaitPool(max uint32, new func() any) *WaitPool {
	p := &WaitPool{pool: sync.Pool{New: new}, max: max}
	p.cond = sync.Cond{L: &p.lock}
	return p
}

func (p *WaitPool) Get() any {
	if p.max != 0 {
		p.lock.Lock()
		for p.count.Load() >= p.max {
			p.cond.Wait()
		}
		p.count.Add(1)
		p.lock.Unlock()
	}
	return p.pool.Get()
}

func (p *WaitPool) Put(x any) {
	p.pool.Put(x)
	if p.max == 0 {
		return
	}
	p.count.Add(^uint32(0))
	p.cond.Signal()
}

func (device *Device) PopulatePools() {
	device.pool.outboundElementsSlice = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		s := make([]*QueueOutboundElement, 0, device.BatchSize())
		return &s
	})
	device.pool.inboundElementsSlice = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		s := make([]*QueueInboundElement, 0, device.BatchSize())
		return &s
	})
	device.pool.messageBuffers = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new([MaxMessageSize]byte)
	})
	device.pool.inboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new(QueueInboundElement)
	})
	device.pool.outboundElements = NewWaitPool(PreallocatedBuffersPerPool, func() any {
		return new(QueueOutboundElement)
	})
}

func (device *Device) GetOutboundElementsSlice() *[]*QueueOutboundElement {
	return device.pool.outboundElementsSlice.Get().(*[]*QueueOutboundElement)
}

func (device *Device) PutOutboundElementsSlice(s *[]*QueueOutboundElement) {
	for i := range *s {
		(*s)[i] = nil
	}
	*s = (*s)[:0]
	device.pool.outboundElementsSlice.Put(s)
}

func (device *Device) GetInboundElementsSlice() *[]*QueueInboundElement {
	return device.pool.inboundElementsSlice.Get().(*[]*QueueInboundElement)
}

func (device *Device) PutInboundElementsSlice(s *[]*QueueInboundElement) {
	for i := range *s {
		(*s)[i] = nil
	}
	*s = (*s)[:0]
	device.pool.inboundElementsSlice.Put(s)
}

func (device *Device) GetMessageBuffer() *[MaxMessageSize]byte {
	return device.pool.messageBuffers.Get().(*[MaxMessageSize]byte)
}

func (device *Device) PutMessageBuffer(msg *[MaxMessageSize]byte) {
	device.pool.messageBuffers.Put(msg)
}

func (device *Device) GetInboundElement() *QueueInboundElement {
	return device.pool.inboundElements.Get().(*QueueInboundElement)
}

func (device *Device) PutInboundElement(elem *QueueInboundElement) {
	elem.clearPointers()
	device.pool.inboundElements.Put(elem)
}

func (device *Device) GetOutboundElement() *QueueOutboundElement {
	return device.pool.outboundElements.Get().(*QueueOutboundElement)
}

func (device *Device) PutOutboundElement(elem *QueueOutboundElement) {
	elem.clearPointers()
	device.pool.outboundElements.Put(elem)
}
