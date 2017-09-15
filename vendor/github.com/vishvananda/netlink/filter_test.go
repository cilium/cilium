// +build linux

package netlink

import (
	"syscall"
	"testing"
)

func TestFilterAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "bar"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	redir, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(redir); err != nil {
		t.Fatal(err)
	}
	qdisc := &Ingress{
		QdiscAttrs: QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    MakeHandle(0xffff, 0),
			Parent:    HANDLE_INGRESS,
		},
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := QdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	_, ok := qdiscs[0].(*Ingress)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}
	filter := &U32{
		FilterAttrs: FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    MakeHandle(0xffff, 0),
			Priority:  1,
			Protocol:  syscall.ETH_P_IP,
		},
		RedirIndex: redir.Attrs().Index,
	}
	if err := FilterAdd(filter); err != nil {
		t.Fatal(err)
	}
	filters, err := FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 {
		t.Fatal("Failed to add filter")
	}
	if err := FilterDel(filter); err != nil {
		t.Fatal(err)
	}
	filters, err = FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 0 {
		t.Fatal("Failed to remove filter")
	}
	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = QdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestFilterFwAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "bar"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	redir, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(redir); err != nil {
		t.Fatal(err)
	}
	attrs := QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    MakeHandle(0xffff, 0),
		Parent:    HANDLE_ROOT,
	}
	qdisc := NewHtb(attrs)
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := QdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	_, ok := qdiscs[0].(*Htb)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}

	classattrs := ClassAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    MakeHandle(0xffff, 0),
		Handle:    MakeHandle(0xffff, 2),
	}

	htbclassattrs := HtbClassAttrs{
		Rate:    1234000,
		Cbuffer: 1690,
	}
	class := NewHtbClass(classattrs, htbclassattrs)
	if err := ClassAdd(class); err != nil {
		t.Fatal(err)
	}
	classes, err := ClassList(link, MakeHandle(0xffff, 2))
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 1 {
		t.Fatal("Failed to add class")
	}

	filterattrs := FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    MakeHandle(0xffff, 0),
		Handle:    MakeHandle(0, 0x6),
		Priority:  1,
		Protocol:  syscall.ETH_P_IP,
	}
	fwattrs := FilterFwAttrs{
		Buffer:   12345,
		Rate:     1234,
		PeakRate: 2345,
		Action:   TC_POLICE_SHOT,
		ClassId:  MakeHandle(0xffff, 2),
	}

	filter, err := NewFw(filterattrs, fwattrs)
	if err != nil {
		t.Fatal(err)
	}

	if err := FilterAdd(filter); err != nil {
		t.Fatal(err)
	}

	filters, err := FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 {
		t.Fatal("Failed to add filter")
	}
	fw, ok := filters[0].(*Fw)
	if !ok {
		t.Fatal("Filter is the wrong type")
	}
	if fw.Police.Rate.Rate != filter.Police.Rate.Rate {
		t.Fatal("Police Rate doesn't match")
	}
	for i := range fw.Rtab {
		if fw.Rtab[i] != filter.Rtab[i] {
			t.Fatal("Rtab doesn't match")
		}
		if fw.Ptab[i] != filter.Ptab[i] {
			t.Fatal("Ptab doesn't match")
		}
	}
	if fw.ClassId != filter.ClassId {
		t.Fatal("ClassId doesn't match")
	}
	if fw.InDev != filter.InDev {
		t.Fatal("InDev doesn't match")
	}
	if fw.AvRate != filter.AvRate {
		t.Fatal("AvRate doesn't match")
	}

	if err := FilterDel(filter); err != nil {
		t.Fatal(err)
	}
	filters, err = FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 0 {
		t.Fatal("Failed to remove filter")
	}
	if err := ClassDel(class); err != nil {
		t.Fatal(err)
	}
	classes, err = ClassList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(classes) != 0 {
		t.Fatal("Failed to remove class")
	}

	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = QdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestFilterU32BpfAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "bar"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	redir, err := LinkByName("bar")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(redir); err != nil {
		t.Fatal(err)
	}
	qdisc := &Ingress{
		QdiscAttrs: QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    MakeHandle(0xffff, 0),
			Parent:    HANDLE_INGRESS,
		},
	}
	if err := QdiscAdd(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err := QdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	_, ok := qdiscs[0].(*Ingress)
	if !ok {
		t.Fatal("Qdisc is the wrong type")
	}

	fd, err := loadSimpleBpf(BPF_PROG_TYPE_SCHED_ACT, 1)
	if err != nil {
		t.Skipf("Loading bpf program failed: %s", err)
	}
	filter := &U32{
		FilterAttrs: FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    MakeHandle(0xffff, 0),
			Priority:  1,
			Protocol:  syscall.ETH_P_ALL,
		},
		ClassId: MakeHandle(1, 1),
		Actions: []Action{
			&BpfAction{Fd: fd, Name: "simple"},
			&MirredAction{
				ActionAttrs: ActionAttrs{
					Action: TC_ACT_STOLEN,
				},
				MirredAction: TCA_EGRESS_REDIR,
				Ifindex:      redir.Attrs().Index,
			},
		},
	}

	if err := FilterAdd(filter); err != nil {
		t.Fatal(err)
	}

	filters, err := FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 {
		t.Fatal("Failed to add filter")
	}
	u32, ok := filters[0].(*U32)
	if !ok {
		t.Fatal("Filter is the wrong type")
	}

	if len(u32.Actions) != 2 {
		t.Fatalf("Too few Actions in filter")
	}
	bpfAction, ok := u32.Actions[0].(*BpfAction)
	if !ok {
		t.Fatal("Action[0] is the wrong type")
	}
	if bpfAction.Fd != fd {
		t.Fatal("Action Fd does not match")
	}
	if _, ok := u32.Actions[1].(*MirredAction); !ok {
		t.Fatal("Action[1] is the wrong type")
	}

	if err := FilterDel(filter); err != nil {
		t.Fatal(err)
	}
	filters, err = FilterList(link, MakeHandle(0xffff, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 0 {
		t.Fatal("Failed to remove filter")
	}

	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = QdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}

func TestFilterClsActBpfAddDel(t *testing.T) {
	tearDown := setUpNetlinkTest(t)
	defer tearDown()
	if err := LinkAdd(&Ifb{LinkAttrs{Name: "foo"}}); err != nil {
		t.Fatal(err)
	}
	link, err := LinkByName("foo")
	if err != nil {
		t.Fatal(err)
	}
	if err := LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	attrs := QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    MakeHandle(0xffff, 0),
		Parent:    HANDLE_CLSACT,
	}
	qdisc := &GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}
	// This feature was added in kernel 4.5
	if err := QdiscAdd(qdisc); err != nil {
		t.Skipf("Failed adding clsact qdisc, unsupported kernel")
	}
	qdiscs, err := QdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 1 {
		t.Fatal("Failed to add qdisc")
	}
	if q, ok := qdiscs[0].(*GenericQdisc); !ok || q.Type() != "clsact" {
		t.Fatal("qdisc is the wrong type")
	}

	filterattrs := FilterAttrs{
		LinkIndex: link.Attrs().Index,
		Parent:    HANDLE_MIN_EGRESS,
		Handle:    MakeHandle(0, 1),
		Protocol:  syscall.ETH_P_ALL,
		Priority:  1,
	}
	fd, err := loadSimpleBpf(BPF_PROG_TYPE_SCHED_CLS, 1)
	if err != nil {
		t.Skipf("Loading bpf program failed: %s", err)
	}
	filter := &BpfFilter{
		FilterAttrs:  filterattrs,
		Fd:           fd,
		Name:         "simple",
		DirectAction: true,
	}
	if filter.Fd < 0 {
		t.Skipf("Failed to load bpf program")
	}

	if err := FilterAdd(filter); err != nil {
		t.Fatal(err)
	}

	filters, err := FilterList(link, HANDLE_MIN_EGRESS)
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 1 {
		t.Fatal("Failed to add filter")
	}
	bpf, ok := filters[0].(*BpfFilter)
	if !ok {
		t.Fatal("Filter is the wrong type")
	}

	if bpf.Fd != filter.Fd {
		t.Fatal("Filter Fd does not match")
	}
	if bpf.DirectAction != filter.DirectAction {
		t.Fatal("Filter DirectAction does not match")
	}

	if err := FilterDel(filter); err != nil {
		t.Fatal(err)
	}
	filters, err = FilterList(link, HANDLE_MIN_EGRESS)
	if err != nil {
		t.Fatal(err)
	}
	if len(filters) != 0 {
		t.Fatal("Failed to remove filter")
	}

	if err := QdiscDel(qdisc); err != nil {
		t.Fatal(err)
	}
	qdiscs, err = QdiscList(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(qdiscs) != 0 {
		t.Fatal("Failed to remove qdisc")
	}
}
