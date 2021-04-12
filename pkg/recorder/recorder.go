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
	srcPrefix net.IPNet
	srcPort   uint16
	dstPrefix net.IPNet
	dstPort   uint16
	proto     u8proto.U8proto
}

type recorderMask struct {
	srcMask net.IPMask
	srcPort uint16
	dstMask net.IPMask
	dstPort uint16
	proto   u8proto.U8proto
}

type RecInfo struct {
	id      ID
	capLen  uint16
	filters []RecorderTuple
}

type RecMask struct {
	users int
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
		srcMask: make([]byte, len(t.srcPrefix.Mask)),
		dstMask: make([]byte, len(t.dstPrefix.Mask)),
	}
	if t.srcPort != 0 {
		m.srcPort = 0xffff
	}
	if t.dstPort != 0 {
		m.dstPort = 0xffff
	}
	if t.proto != 0 {
		m.proto = 0xff
	}
	copy(m.srcMask, t.srcPrefix.Mask)
	copy(m.dstMask, t.dstPrefix.Mask)
	return m
}

func hashMask(x *recorderMask) string {
	return fmt.Sprintf("%s/%s/%x/%x/%x",
		x.srcMask.String(), x.dstMask.String(),
		int(x.srcPort), int(x.dstPort), int(x.proto))
}

func hashTuple(x *RecorderTuple) string {
	return fmt.Sprintf("%s/%s/%x/%x/%x",
		x.srcPrefix.String(), x.dstPrefix.String(),
		int(x.srcPort), int(x.dstPort), int(x.proto))
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
	r.queue.add = append(r.queue.add, &ri.filters[i])
}

func (r *Recorder) queueDelDatapathFilter(ri *RecInfo, i int) {
	if r.queue.ri == nil {
		r.queue.ri = ri
	}
	filter := &ri.filters[i]
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
	for i, filter := range ri.filters {
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
		delete(r.recByID, ri.id)
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
		r.recByID[ri.id] = ri
	}
	triggerRegen := false
	for i, filter := range ri.filters {
		mask := convertTupleToMask(filter)
		maskHash := hashMask(&mask)
		if rm, found := r.recMask[maskHash]; found {
			rm.users++
		} else {
			rm := &RecMask{
				users: 1,
				mask:  mask,
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
		id:      recInfo.id,
		capLen:  recInfo.capLen,
		filters: []RecorderTuple{},
	}
	for _, filter := range recInfo.filters {
		f := RecorderTuple{
			srcPort: filter.srcPort,
			dstPort: filter.dstPort,
			proto:   filter.proto,
		}
		f.srcPrefix = deepCopyPrefix(filter.srcPrefix)
		f.dstPrefix = deepCopyPrefix(filter.dstPrefix)
		ri.filters = append(ri.filters, f)
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
	if recInfoCur, found := r.recByID[recInfoCpy.id]; found {
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
		id:      ID(*mo.ID),
		capLen:  uint16(mo.CaptureLength),
		filters: []RecorderTuple{},
	}
	for _, mf := range mo.Filters {
		f := RecorderTuple{}
		ipDst, prefix, err := net.ParseCIDR(mf.DstPrefix)
		if err != nil {
			return nil, err
		}
		f.dstPrefix = *prefix
		ipSrc, prefix, err := net.ParseCIDR(mf.SrcPrefix)
		if err != nil {
			return nil, err
		}
		f.srcPrefix = *prefix
		if (ipDst.To4() == nil) != (ipSrc.To4() == nil) {
			return nil, fmt.Errorf("Recorder source (%s) and destination (%s) prefix must be same protocol version",
				f.srcPrefix, f.dstPrefix)
		}
		if !option.Config.EnableIPv4 && ipDst.To4() != nil ||
			!option.Config.EnableIPv6 && ipDst.To4() == nil {
			return nil, fmt.Errorf("Recorder source (%s) and destination (%s) prefix not supported by agent config",
				f.srcPrefix, f.dstPrefix)
		}
		port, err := strconv.ParseUint(mf.DstPort, 10, 16)
		if err != nil {
			return nil, err
		}
		f.dstPort = uint16(port)
		port, err = strconv.ParseUint(mf.SrcPort, 10, 16)
		if err != nil {
			return nil, err
		}
		f.srcPort = uint16(port)
		switch mf.Protocol {
		case models.RecorderFilterProtocolTCP:
			f.proto = u8proto.TCP
		case models.RecorderFilterProtocolUDP:
			f.proto = u8proto.UDP
		case models.RecorderFilterProtocolANY:
			f.proto = u8proto.ANY
		default:
			return nil, fmt.Errorf("Recorder protocol %s not supported by backend",
				mf.Protocol)
		}
		ri.filters = append(ri.filters, f)
	}
	return ri, nil
}

func RecorderToModel(ri *RecInfo) (*models.RecorderSpec, error) {
	id := int64(ri.id)
	mo := &models.RecorderSpec{
		ID:            &id,
		Filters:       []*models.RecorderFilter{},
		CaptureLength: int64(ri.capLen),
	}
	for _, rf := range ri.filters {
		mf := &models.RecorderFilter{}
		mf.DstPrefix = rf.dstPrefix.String()
		mf.SrcPrefix = rf.srcPrefix.String()
		mf.DstPort = fmt.Sprintf("%d", int(rf.dstPort))
		mf.SrcPort = fmt.Sprintf("%d", int(rf.srcPort))
		switch rf.proto {
		case u8proto.TCP:
			mf.Protocol = models.RecorderFilterProtocolTCP
		case u8proto.UDP:
			mf.Protocol = models.RecorderFilterProtocolUDP
		case u8proto.ANY:
			mf.Protocol = models.RecorderFilterProtocolANY
		default:
			return nil, fmt.Errorf("Recorder protocol %d not supported by model",
				int(rf.proto))
		}
		mo.Filters = append(mo.Filters, mf)
	}
	return mo, nil
}

func RecorderMaskToModel(rm *RecMask) *models.RecorderMaskSpec {
	mo := &models.RecorderMaskSpec{
		Users: int64(rm.users),
	}
	mo.DstPrefixMask = rm.mask.dstMask.String()
	mo.SrcPrefixMask = rm.mask.srcMask.String()
	mo.DstPortMask = fmt.Sprintf("%x", int(rm.mask.dstPort))
	mo.SrcPortMask = fmt.Sprintf("%x", int(rm.mask.srcPort))
	mo.ProtocolMask = fmt.Sprintf("%x", int(rm.mask.proto))
	return mo
}
