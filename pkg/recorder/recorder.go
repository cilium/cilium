// Copyright 2021 Authors of Cilium
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

package recorder

import (
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	subsystem = "recorder"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsystem)

type ID uint16

type RecorderTuple struct {
	SrcPrefix net.IPNet
	SrcPort   uint16
	DstPrefix net.IPNet
	DstPort   uint16
	Proto     u8proto.U8proto
}

type recorderMask struct {
	srcMask net.IPMask
	srcPort uint16
	dstMask net.IPMask
	dstPort uint16
	proto   u8proto.U8proto
}

type RecInfo struct {
	ID      ID
	CapLen  uint16
	Filters []RecorderTuple
}

type RecMask struct {
	users int
	prio  int
	mask  recorderMask
}

type recQueue struct {
	ri  *RecInfo
	add []*RecorderTuple
	del []*RecorderTuple
}

type Recorder struct {
	lock.RWMutex
	recByID map[ID]*RecInfo
	recMask map[string]*RecMask
	queue   recQueue
}

func NewRecorder() *Recorder {
	rec := &Recorder{
		recByID: map[ID]*RecInfo{},
		recMask: map[string]*RecMask{},
		queue: recQueue{
			add: []*RecorderTuple{},
			del: []*RecorderTuple{},
		},
	}
	return rec
}

func convertTupleToMask(t RecorderTuple) recorderMask {
	m := recorderMask{
		srcMask: make([]byte, len(t.SrcPrefix.Mask)),
		dstMask: make([]byte, len(t.DstPrefix.Mask)),
	}
	if t.SrcPort != 0 {
		m.srcPort = 0xffff
	}
	if t.DstPort != 0 {
		m.dstPort = 0xffff
	}
	if t.Proto != 0 {
		m.proto = 0xff
	}
	copy(m.srcMask, t.SrcPrefix.Mask)
	copy(m.dstMask, t.DstPrefix.Mask)
	return m
}

func countMaskOnes(m recorderMask) int {
	ones := 0
	onesSrc, _ := m.srcMask.Size()
	onesDst, _ := m.dstMask.Size()
	ones += onesSrc + onesDst
	if m.srcPort == 0xffff {
		ones += 16
	}
	if m.dstPort == 0xffff {
		ones += 16
	}
	if m.proto == 0xff {
		ones += 8
	}
	return ones
}

func hashMask(x *recorderMask) string {
	return fmt.Sprintf("%s/%s/%x/%x/%x",
		x.srcMask.String(), x.dstMask.String(),
		int(x.srcPort), int(x.dstPort), int(x.proto))
}

func hashTuple(x *RecorderTuple) string {
	return fmt.Sprintf("%s/%s/%x/%x/%x",
		x.SrcPrefix.String(), x.DstPrefix.String(),
		int(x.SrcPort), int(x.DstPort), int(x.Proto))
}

func (r *Recorder) triggerDatapathRegenerate() error {
	return nil
}

func (r *Recorder) triggerMapUpsert(ri *RecInfo, t *RecorderTuple) error {
	return nil
}

func (r *Recorder) triggerMapDelete(ri *RecInfo, t *RecorderTuple) error {
	return nil
}

func (r *Recorder) applyDatapath(regen bool) error {
	for _, e := range r.queue.add {
		r.triggerMapUpsert(r.queue.ri, e)
	}
	r.queue.add = []*RecorderTuple{}
	for _, e := range r.queue.del {
		r.triggerMapDelete(r.queue.ri, e)
	}
	r.queue.del = []*RecorderTuple{}
	r.queue.ri = nil
	if regen {
		log.Debugf("Recorder Masks: %v", r.recMask)
		// If datapath masks did not change, then there is of course
		// also no need to trigger a regeneration since map updates
		// suffice (which is also much faster).
		return r.triggerDatapathRegenerate()
	}
	return nil
}

func queuePurge(q []*RecorderTuple, i int) []*RecorderTuple {
	q[i] = q[len(q)-1]
	q[len(q)-1] = nil
	return q[:len(q)-1]
}

func (r *Recorder) queueAddDatapathFilter(ri *RecInfo, i int) {
	if r.queue.ri == nil {
		r.queue.ri = ri
	}
	r.queue.add = append(r.queue.add, &ri.Filters[i])
}

func (r *Recorder) queueDelDatapathFilter(ri *RecInfo, i int) {
	if r.queue.ri == nil {
		r.queue.ri = ri
	}
	filter := &ri.Filters[i]
	hash := hashTuple(filter)
	// If the recorder updated an existing filter element which sits
	// in both queues, then we do not need any change in the BPF data
	// path, and can avoid temporary recorder disruption. Hence, add/del
	// queues strictly only ever contain entries that need change.
	for i, e := range r.queue.add {
		if hashTuple(e) == hash {
			r.queue.add = queuePurge(r.queue.add, i)
			return
		}
	}
	r.queue.del = append(r.queue.del, filter)
}

func (r *Recorder) deleteRecInfoLocked(ri *RecInfo, withID bool) bool {
	triggerRegen := false
	for i, filter := range ri.Filters {
		mask := convertTupleToMask(filter)
		maskHash := hashMask(&mask)
		if rm, found := r.recMask[maskHash]; found {
			rm.users--
			if rm.users == 0 {
				delete(r.recMask, maskHash)
				triggerRegen = true
			}
		}
		r.queueDelDatapathFilter(ri, i)
	}
	if withID {
		delete(r.recByID, ri.ID)
	}
	return triggerRegen
}

// DeleteRecorder will delete an existing recorder object based on its unique
// identifier. If needed, it will also update datapath maps to purge the
// recorder filters from the BPF maps as well as triggering a reinitialization
// of the XDP datapath if the mask set has changed.
func (r *Recorder) DeleteRecorder(id ID) (bool, error) {
	r.Lock()
	defer r.Unlock()
	if recInfo, found := r.recByID[id]; found {
		return true, r.applyDatapath(r.deleteRecInfoLocked(recInfo, true))
	}
	return false, nil
}

func (r *Recorder) createRecInfoLocked(ri *RecInfo, withID bool) bool {
	if withID {
		r.recByID[ri.ID] = ri
	}
	triggerRegen := false
	for i, filter := range ri.Filters {
		mask := convertTupleToMask(filter)
		maskHash := hashMask(&mask)
		if rm, found := r.recMask[maskHash]; found {
			rm.users++
		} else {
			ones := countMaskOnes(mask)
			rm := &RecMask{
				users: 1,
				mask:  mask,
				prio:  ones,
			}
			r.recMask[maskHash] = rm
			triggerRegen = true
		}
		r.queueAddDatapathFilter(ri, i)
	}
	return triggerRegen
}

func (r *Recorder) updateRecInfoLocked(riNew, riOld *RecInfo) error {
	triggerRegen := false
	if r.createRecInfoLocked(riNew, true) {
		triggerRegen = true
	}
	if r.deleteRecInfoLocked(riOld, false) {
		triggerRegen = true
	}
	return r.applyDatapath(triggerRegen)
}

func deepCopyPrefix(p net.IPNet) net.IPNet {
	out := net.IPNet{
		IP:   make([]byte, len(p.IP)),
		Mask: make([]byte, len(p.Mask)),
	}
	copy(out.IP, p.IP)
	copy(out.Mask, p.Mask)
	return out
}

func deepCopyRecInfo(recInfo *RecInfo) *RecInfo {
	ri := &RecInfo{
		ID:      recInfo.ID,
		CapLen:  recInfo.CapLen,
		Filters: []RecorderTuple{},
	}
	for _, filter := range recInfo.Filters {
		f := RecorderTuple{
			SrcPort: filter.SrcPort,
			DstPort: filter.DstPort,
			Proto:   filter.Proto,
		}
		f.SrcPrefix = deepCopyPrefix(filter.SrcPrefix)
		f.DstPrefix = deepCopyPrefix(filter.DstPrefix)
		ri.Filters = append(ri.Filters, f)
	}
	return ri
}

// UpsertRecorder will create a new or update an existing recorder object
// based on its unique identifier. If needed, it will also update datapath
// maps to insert new or remove obsolete recorder filters from the BPF maps
// as well as triggering a reinitialization of the XDP datapath if the mask
// set has changed.
func (r *Recorder) UpsertRecorder(recInfoNew *RecInfo) (bool, error) {
	if !option.Config.EnableRecorder {
		return false, fmt.Errorf("Ignoring recorder request due to --%s being disabled in agent",
			option.EnableRecorder)
	}
	recInfoCpy := deepCopyRecInfo(recInfoNew)
	r.Lock()
	defer r.Unlock()
	if recInfoCur, found := r.recByID[recInfoCpy.ID]; found {
		return false, r.updateRecInfoLocked(recInfoCpy, recInfoCur)
	} else {
		return true, r.applyDatapath(r.createRecInfoLocked(recInfoCpy, true))
	}
}

func (r *Recorder) retrieveRecorderLocked(id ID) (*RecInfo, error) {
	if recInfo, found := r.recByID[id]; found {
		return deepCopyRecInfo(recInfo), nil
	} else {
		return nil, fmt.Errorf("Recorder id %d not found", int(id))
	}
}

// RetrieveRecorder will return an existing recorder object based on its
// unique identifier. The returned object is a deep copy of the original
// one tracked by the recorder infrastructure, so it can be freely changed
// without affecting the original recorder object.
func (r *Recorder) RetrieveRecorder(id ID) (*RecInfo, error) {
	r.RLock()
	defer r.RUnlock()
	return r.retrieveRecorderLocked(id)
}

// RetrieveRecorderSet will return a list of all existing recorder objects.
func (r *Recorder) RetrieveRecorderSet() []*RecInfo {
	recList := []*RecInfo{}
	r.RLock()
	defer r.RUnlock()
	for id := range r.recByID {
		rec, _ := r.retrieveRecorderLocked(id)
		recList = append(recList, rec)
	}
	return recList
}

func deepCopyMask(m net.IPMask) net.IPMask {
	out := make([]byte, len(m))
	copy(out, m)
	return out
}

func deepCopyRecMask(recMask *RecMask) *RecMask {
	rm := &RecMask{
		users: recMask.users,
		prio:  recMask.prio,
		mask: recorderMask{
			srcPort: recMask.mask.srcPort,
			dstPort: recMask.mask.dstPort,
			proto:   recMask.mask.proto,
		},
	}
	rm.mask.srcMask = deepCopyMask(recMask.mask.srcMask)
	rm.mask.dstMask = deepCopyMask(recMask.mask.dstMask)
	return rm
}

// RetrieveRecorderMaskSet will return a list of all existing recorder masks.
func (r *Recorder) RetrieveRecorderMaskSet() []*RecMask {
	recMaskList := []*RecMask{}
	r.RLock()
	defer r.RUnlock()
	for _, mask := range r.recMask {
		maskCpy := deepCopyRecMask(mask)
		recMaskList = append(recMaskList, maskCpy)
	}
	return recMaskList
}

func ModelToRecorder(mo *models.RecorderSpec) (*RecInfo, error) {
	if mo.ID == nil {
		return nil, fmt.Errorf("Recorder model ID must be defined")
	}
	ri := &RecInfo{
		ID:      ID(*mo.ID),
		CapLen:  uint16(mo.CaptureLength),
		Filters: []RecorderTuple{},
	}
	for _, mf := range mo.Filters {
		f := RecorderTuple{}
		ipDst, prefix, err := net.ParseCIDR(mf.DstPrefix)
		if err != nil {
			return nil, err
		}
		f.DstPrefix = *prefix
		ipSrc, prefix, err := net.ParseCIDR(mf.SrcPrefix)
		if err != nil {
			return nil, err
		}
		f.SrcPrefix = *prefix
		if (ipDst.To4() == nil) != (ipSrc.To4() == nil) {
			return nil, fmt.Errorf("Recorder source (%s) and destination (%s) prefix must be same protocol version",
				f.SrcPrefix, f.DstPrefix)
		}
		if !option.Config.EnableIPv4 && ipDst.To4() != nil ||
			!option.Config.EnableIPv6 && ipDst.To4() == nil {
			return nil, fmt.Errorf("Recorder source (%s) and destination (%s) prefix not supported by agent config",
				f.SrcPrefix, f.DstPrefix)
		}
		port, err := strconv.ParseUint(mf.DstPort, 10, 16)
		if err != nil {
			return nil, err
		}
		f.DstPort = uint16(port)
		port, err = strconv.ParseUint(mf.SrcPort, 10, 16)
		if err != nil {
			return nil, err
		}
		f.SrcPort = uint16(port)
		switch mf.Protocol {
		case models.RecorderFilterProtocolTCP:
			f.Proto = u8proto.TCP
		case models.RecorderFilterProtocolUDP:
			f.Proto = u8proto.UDP
		case models.RecorderFilterProtocolANY:
			f.Proto = u8proto.ANY
		default:
			return nil, fmt.Errorf("Recorder protocol %s not supported by backend",
				mf.Protocol)
		}
		ri.Filters = append(ri.Filters, f)
	}
	return ri, nil
}

func RecorderToModel(ri *RecInfo) (*models.RecorderSpec, error) {
	id := int64(ri.ID)
	mo := &models.RecorderSpec{
		ID:            &id,
		Filters:       []*models.RecorderFilter{},
		CaptureLength: int64(ri.CapLen),
	}
	for _, rf := range ri.Filters {
		mf := &models.RecorderFilter{}
		mf.DstPrefix = rf.DstPrefix.String()
		mf.SrcPrefix = rf.SrcPrefix.String()
		mf.DstPort = fmt.Sprintf("%d", int(rf.DstPort))
		mf.SrcPort = fmt.Sprintf("%d", int(rf.SrcPort))
		switch rf.Proto {
		case u8proto.TCP:
			mf.Protocol = models.RecorderFilterProtocolTCP
		case u8proto.UDP:
			mf.Protocol = models.RecorderFilterProtocolUDP
		case u8proto.ANY:
			mf.Protocol = models.RecorderFilterProtocolANY
		default:
			return nil, fmt.Errorf("Recorder protocol %d not supported by model",
				int(rf.Proto))
		}
		mo.Filters = append(mo.Filters, mf)
	}
	return mo, nil
}

func RecorderMaskToModel(rm *RecMask) *models.RecorderMaskSpec {
	mo := &models.RecorderMaskSpec{
		Users:    int64(rm.users),
		Priority: int64(rm.prio),
	}
	mo.DstPrefixMask = rm.mask.dstMask.String()
	mo.SrcPrefixMask = rm.mask.srcMask.String()
	mo.DstPortMask = fmt.Sprintf("%x", int(rm.mask.dstPort))
	mo.SrcPortMask = fmt.Sprintf("%x", int(rm.mask.srcPort))
	mo.ProtocolMask = fmt.Sprintf("%x", int(rm.mask.proto))
	return mo
}
