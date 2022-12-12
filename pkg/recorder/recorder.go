// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package recorder

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/common"
	"github.com/cilium/cilium/pkg/datapath/loader"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/recorder"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	subsystem = "recorder"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, subsystem)

type ID uint16

// +k8s:deepcopy-gen=true
type RecorderTuple struct {
	SrcPrefix cidr.CIDR
	SrcPort   uint16
	DstPrefix cidr.CIDR
	DstPort   uint16
	Proto     u8proto.U8proto
}

// +k8s:deepcopy-gen=true
type RecorderMask struct {
	srcMask net.IPMask
	srcPort uint16
	dstMask net.IPMask
	dstPort uint16
	proto   u8proto.U8proto
}

// +k8s:deepcopy-gen=true
type RecInfo struct {
	ID      ID
	CapLen  uint16
	Filters []RecorderTuple
}

// +k8s:deepcopy-gen=true
type RecMask struct {
	users int
	prio  int
	mask  RecorderMask
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
	ctx     context.Context
	owner   datapath.BaseProgramOwner
}

// NewRecorder initializes the main recorder infrastructure once upon agent
// bootstrap for tracking tuple insertions and masks that need to be pushed
// down into the BPF datapath. Given we currently do not support restore
// functionality, it also flushes prior existing recorder objects from the
// BPF maps.
func NewRecorder(ctx context.Context, owner datapath.BaseProgramOwner) (*Recorder, error) {
	rec := &Recorder{
		recByID: map[ID]*RecInfo{},
		recMask: map[string]*RecMask{},
		queue: recQueue{
			add: []*RecorderTuple{},
			del: []*RecorderTuple{},
		},
		ctx:   ctx,
		owner: owner,
	}
	if option.Config.EnableRecorder {
		maps := []*bpf.Map{}
		if option.Config.EnableIPv4 {
			t := &recorder.CaptureWcard4{}
			maps = append(maps, t.Map())
		}
		if option.Config.EnableIPv6 {
			t := &recorder.CaptureWcard6{}
			maps = append(maps, t.Map())
		}
		for _, m := range maps {
			if err := m.OpenOrCreate(); err != nil {
				return nil, err
			}
			if err := m.DeleteAll(); err != nil {
				return nil, err
			}
		}
	}
	return rec, nil
}

func convertTupleToMask(t RecorderTuple) RecorderMask {
	m := RecorderMask{
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

func countMaskOnes(m RecorderMask) int {
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

func hashMask(x *RecorderMask) string {
	return fmt.Sprintf("%s/%s/%x/%x/%x",
		x.srcMask.String(), x.dstMask.String(),
		int(x.srcPort), int(x.dstPort), int(x.proto))
}

func hashTuple(x *RecorderTuple) string {
	return fmt.Sprintf("%s/%s/%x/%x/%x",
		x.SrcPrefix.String(), x.DstPrefix.String(),
		int(x.SrcPort), int(x.DstPort), int(x.Proto))
}

func (t *RecorderTuple) isIPv4() bool {
	_, bits := t.SrcPrefix.Mask.Size()
	return bits == 32
}

func (m *RecorderMask) isIPv4() bool {
	_, bits := m.srcMask.Size()
	return bits == 32
}

func (m *RecorderMask) genMacroSpec() string {
	onesSrc, _ := m.srcMask.Size()
	onesDst, _ := m.dstMask.Size()

	spec := "{"
	if m.isIPv4() {
		spec += fmt.Sprintf(".daddr=__constant_htonl(0x%s),", m.dstMask.String())
		spec += fmt.Sprintf(".saddr=__constant_htonl(0x%s),", m.srcMask.String())
	} else {
		spec += fmt.Sprintf(".daddr={.addr={%s}},", common.GoArray2C(m.dstMask))
		spec += fmt.Sprintf(".saddr={.addr={%s}},", common.GoArray2C(m.srcMask))
	}
	spec += fmt.Sprintf(".dmask=%d,", onesDst)
	spec += fmt.Sprintf(".smask=%d,", onesSrc)
	spec += fmt.Sprintf(".dport=%#x,", m.dstPort)
	spec += fmt.Sprintf(".sport=%#x,", m.srcPort)
	spec += fmt.Sprintf(".nexthdr=%#x,", uint8(m.proto))
	spec += "},"
	return spec
}

func (r *Recorder) orderedMaskSets() ([]*RecMask, []*RecMask) {
	ordered4 := []*RecMask{}
	ordered6 := []*RecMask{}
	for _, m := range r.recMask {
		if m.mask.isIPv4() {
			ordered4 = append(ordered4, m)
		} else {
			ordered6 = append(ordered6, m)
		}
	}
	sort.Slice(ordered4, func(i, j int) bool {
		return ordered4[i].prio > ordered4[j].prio
	})
	sort.Slice(ordered6, func(i, j int) bool {
		return ordered6[i].prio > ordered6[j].prio
	})
	return ordered4, ordered6
}

func (r *Recorder) triggerDatapathRegenerate() error {
	var masks4, masks6 string
	l := &loader.Loader{}
	extraCArgs := []string{}
	if len(r.recMask) == 0 {
		extraCArgs = append(extraCArgs, "-Dcapture_enabled=0")
	} else {
		extraCArgs = append(extraCArgs, "-Dcapture_enabled=1")
		ordered4, ordered6 := r.orderedMaskSets()
		if option.Config.EnableIPv4 {
			masks4 = "-DPREFIX_MASKS4="
			if len(ordered4) == 0 {
				masks4 += " "
			} else {
				for _, m := range ordered4 {
					masks4 += m.mask.genMacroSpec()
				}
			}
			extraCArgs = append(extraCArgs, masks4)
		}
		if option.Config.EnableIPv6 {
			masks6 = "-DPREFIX_MASKS6="
			if len(ordered6) == 0 {
				masks6 += " "
			} else {
				for _, m := range ordered6 {
					masks6 += m.mask.genMacroSpec()
				}
			}
			extraCArgs = append(extraCArgs, masks6)
		}
	}
	err := l.ReinitializeXDP(r.ctx, r.owner, extraCArgs)
	if err != nil {
		log.WithError(err).Warnf("Failed to regenerate datapath with masks: %s / %s",
			masks4, masks6)
	}
	return err
}

func recorderTupleToMapTuple4(ri *RecInfo, t *RecorderTuple) (*recorder.CaptureWcard4, *recorder.CaptureRule4) {
	onesSrc, _ := t.SrcPrefix.Mask.Size()
	onesDst, _ := t.DstPrefix.Mask.Size()

	k := &recorder.CaptureWcard4{
		NextHdr:  uint8(t.Proto),
		DestMask: uint8(onesDst),
		SrcMask:  uint8(onesSrc),
	}
	k.DestPort = byteorder.HostToNetwork16(t.DstPort)
	k.SrcPort = byteorder.HostToNetwork16(t.SrcPort)
	copy(k.DestAddr[:], t.DstPrefix.IP.To4()[:])
	copy(k.SrcAddr[:], t.SrcPrefix.IP.To4()[:])
	v := &recorder.CaptureRule4{
		RuleId: uint16(ri.ID),
		CapLen: uint32(ri.CapLen),
	}
	return k, v
}

func recorderTupleToMapTuple6(ri *RecInfo, t *RecorderTuple) (*recorder.CaptureWcard6, *recorder.CaptureRule6) {
	onesSrc, _ := t.SrcPrefix.Mask.Size()
	onesDst, _ := t.DstPrefix.Mask.Size()

	k := &recorder.CaptureWcard6{
		NextHdr:  uint8(t.Proto),
		DestMask: uint8(onesDst),
		SrcMask:  uint8(onesSrc),
	}
	k.DestPort = byteorder.HostToNetwork16(t.DstPort)
	k.SrcPort = byteorder.HostToNetwork16(t.SrcPort)
	copy(k.DestAddr[:], t.DstPrefix.IP.To16()[:])
	copy(k.SrcAddr[:], t.SrcPrefix.IP.To16()[:])
	v := &recorder.CaptureRule6{
		RuleId: uint16(ri.ID),
		CapLen: uint32(ri.CapLen),
	}
	return k, v
}

func recorderTupleToMapTuple(ri *RecInfo, t *RecorderTuple) (recorder.RecorderKey, recorder.RecorderEntry) {
	var k recorder.RecorderKey
	var v recorder.RecorderEntry
	if t.isIPv4() {
		k, v = recorderTupleToMapTuple4(ri, t)
	} else {
		k, v = recorderTupleToMapTuple6(ri, t)
	}
	return k, v
}

func (r *Recorder) triggerMapUpsert(ri *RecInfo, t *RecorderTuple) error {
	k, v := recorderTupleToMapTuple(ri, t)
	return k.Map().Update(k, v)
}

func (r *Recorder) triggerMapDelete(ri *RecInfo, t *RecorderTuple) error {
	k, _ := recorderTupleToMapTuple(ri, t)
	return k.Map().Delete(k)
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
			if r.queue.ri.CapLen == ri.CapLen {
				r.queue.add = queuePurge(r.queue.add, i)
			}
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
	recInfoCpy := recInfoNew.DeepCopy()
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
		return recInfo.DeepCopy(), nil
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
	recList := make([]*RecInfo, 0, len(r.recByID))
	r.RLock()
	defer r.RUnlock()
	for id := range r.recByID {
		rec, _ := r.retrieveRecorderLocked(id)
		recList = append(recList, rec)
	}
	return recList
}

// RetrieveRecorderMaskSet will return a list of all existing recorder masks.
func (r *Recorder) RetrieveRecorderMaskSet() []*RecMask {
	recMaskList := make([]*RecMask, 0, len(r.recMask))
	r.RLock()
	defer r.RUnlock()
	for _, mask := range r.recMask {
		maskCpy := mask.DeepCopy()
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
		f.DstPrefix = *cidr.NewCIDR(prefix)
		ipSrc, prefix, err := net.ParseCIDR(mf.SrcPrefix)
		if err != nil {
			return nil, err
		}
		f.SrcPrefix = *cidr.NewCIDR(prefix)
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
		case models.RecorderFilterProtocolSCTP:
			f.Proto = u8proto.SCTP
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
		case u8proto.SCTP:
			mf.Protocol = models.RecorderFilterProtocolSCTP
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
