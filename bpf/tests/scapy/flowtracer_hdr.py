from scapy.all import *
from scapy.packet import Packet, bind_layers
from scapy.fields import *

from enum import IntFlag

# A field that is not serialized in the wire
class HiddenLenField(Field):
    def __init__(self, name, default):
        super().__init__(name, default, fmt="!I")
    def addfield(self, pkt, s, val):
        # Don't add anything to the wire
        return s
    def getfield(self, pkt, s):
        return s, getattr(pkt, self.name)
    def i2repr(self, pkt, x):
        return str(x)

# Note: this needs match definitions on lib/flowtracer.h

# TLV types
FT_TLV_INVALID       = 0
FT_TLV_PKT_INFO      = 1
FT_TLV_ING_IFINDEX   = 2
FT_TLV_EGR_IFINDEX   = 3
FT_TLV_CPU           = 4
FT_TLV_ING_TS        = 5
FT_TLV_EGR_TS        = 6
FT_TLV_PKT_SNAPSHOT  = 7
FT_TLV_DBG           = 8
FT_TLV_NODE          = 9
FT_TLV_LB_NODE       = 10
FT_TLV_LB_BACK       = 11

# TLV map (scapy field)
FT_TLV_MAP = {
    FT_TLV_INVALID: "FT_TLV_INVALID",
    FT_TLV_PKT_INFO: "FT_TLV_PKT_INFO",
    FT_TLV_ING_IFINDEX: "FT_TLV_ING_IFINDEX",
    FT_TLV_EGR_IFINDEX: "FT_TLV_EGR_IFINDEX",
    FT_TLV_CPU: "FT_TLV_CPU",
    FT_TLV_ING_TS: "FT_TLV_ING_TS",
    FT_TLV_EGR_TS: "FT_TLV_EGR_TS",
    FT_TLV_PKT_SNAPSHOT: "FT_TLV_PKT_SNAPSHOT",
    FT_TLV_DBG: "FT_TLV_DBG",
    FT_TLV_NODE: "FT_TLV_NODE",
    FT_TLV_LB_NODE: "FT_TLV_LB_NODE",
    FT_TLV_LB_BACK: "FT_TLV_LB_BACK"
}

class FlowTracerTLVBase(Packet):
    name = "TLVBase"
    tlv_type = FT_TLV_INVALID
    tlv_len = 12

    fields_desc = [
        IntField("type", 0),
        ShortField("len", 0),
        StrFixedLenField("pad", b'\x00\x00', length=2),
        IntField("tracepoint", 0)
    ]

    def __init__(self, *args, **kwargs):
        kwargs["type"] = self.__class__.tlv_type
        kwargs["len"] = self.__class__.tlv_len
        super().__init__(*args, **kwargs)

    def guess_payload_class(self, p):
        cls = Raw
        if len(p) < 4:
            return Raw
        next_type = int.from_bytes(p[:4], byteorder='big')
        if next_type in FT_TLV_TYPE_MAP:
            cls = FT_TLV_TYPE_MAP.get(next_type, Raw)
        return cls

class FlowTracerTLVInfo(FlowTracerTLVBase):
    name = "TLVInfo"
    tlv_type = FT_TLV_PKT_INFO
    tlv_len = 36

    fields_desc = FlowTracerTLVBase.fields_desc + [
        IntField("queue_id", 0),
        IntField("pkt_type", 0),
        IntField("hash", 0),
        IntField("mark", 0),
        IntField("gso_segs", 0),
        IntField("gso_size", 0)
    ]

class FlowTracerTLVIngIfindex(FlowTracerTLVBase):
    name = "TLVIngIface"
    tlv_type = FT_TLV_ING_IFINDEX
    tlv_len = 16

    fields_desc = FlowTracerTLVBase.fields_desc + [
        IntField("ifindex", 0),
    ]

class FlowTracerTLVEgrIfindex(FlowTracerTLVBase):
    name = "TLVEgrIface"
    tlv_type = FT_TLV_EGR_IFINDEX
    tlv_len = 16

    fields_desc = FlowTracerTLVBase.fields_desc + [
        IntField("ifindex", 0),
    ]

class FlowTracerTLVCpu(FlowTracerTLVBase):
    name = "TLVCpu"
    tlv_type = FT_TLV_CPU
    tlv_len = 16

    fields_desc = FlowTracerTLVBase.fields_desc + [
        IntField("cpu", 0),
    ]

class FlowTracerTLVIngTs(FlowTracerTLVBase):
    name = "TLVIngTs"
    tlv_type = FT_TLV_ING_TS
    tlv_len = 20

    fields_desc = FlowTracerTLVBase.fields_desc + [
        LongField("ts", 0),
    ]

class FlowTracerTLVEgrTs(FlowTracerTLVBase):
    name = "TLVEgrTs"
    tlv_type = FT_TLV_EGR_TS
    tlv_len = 20

    fields_desc = FlowTracerTLVBase.fields_desc + [
        LongField("ts", 0),
    ]

class FlowTracerTLVDbg(FlowTracerTLVBase):
    name = "TLVDbg"
    tlv_type = FT_TLV_DBG
    tlv_len = 12

    fields_desc = FlowTracerTLVBase.fields_desc

    #TODO: add variable length

class FlowTracerTLVPacketSnap(FlowTracerTLVBase):
    name = "TLVPacketSnap"
    tlv_type = FT_TLV_PKT_SNAPSHOT

    fields_desc = FlowTracerTLVBase.fields_desc + [
        PacketField("data", None, Packet),
    ]

    def __init__(self, *args, **kwargs):
        if "data" in kwargs:
            self.tlv_len = 12 + len(kwargs["data"])
        super().__init__(*args, **kwargs)

class FlowTracerTLVNode(FlowTracerTLVBase):
    name = "TLVNode"
    tlv_type = FT_TLV_NODE
    tlv_len = 20

    fields_desc = FlowTracerTLVBase.fields_desc + [
        LongField("node", 0),
    ]

class FlowTracerTLVLBNode(FlowTracerTLVBase):
    name = "TLVLBNode"
    tlv_type = FT_TLV_LB_NODE
    tlv_len = 20

    fields_desc = FlowTracerTLVBase.fields_desc + [
        LongField("node", 0),
    ]

class FlowTracerTLVLBBackend(FlowTracerTLVBase):
    name = "TLVLBBackend"
    tlv_type = FT_TLV_LB_BACK
    tlv_len = 20

    fields_desc = FlowTracerTLVBase.fields_desc + [
        LongField("backend", 0),
    ]

# For scapy parsing
FT_TLV_TYPE_MAP = {
    FT_TLV_PKT_INFO: FlowTracerTLVInfo,
    FT_TLV_ING_IFINDEX: FlowTracerTLVIngIfindex,
    FT_TLV_EGR_IFINDEX: FlowTracerTLVEgrIfindex,
    FT_TLV_CPU: FlowTracerTLVCpu,
    FT_TLV_ING_TS: FlowTracerTLVIngTs,
    FT_TLV_EGR_TS: FlowTracerTLVEgrTs,
    FT_TLV_PKT_SNAPSHOT: FlowTracerTLVPacketSnap,
    FT_TLV_DBG: FlowTracerTLVDbg,
    FT_TLV_NODE: FlowTracerTLVNode,
    FT_TLV_LB_NODE: FlowTracerTLVLBNode,
    FT_TLV_LB_BACK: FlowTracerTLVLBBackend
}

# Commands
FT_CMD_TRACE_PKT_INFO = (1 << FT_TLV_PKT_INFO)
FT_CMD_TRACE_IIFINDEX = (1 << FT_TLV_ING_IFINDEX)
FT_CMD_TRACE_EIFINDEX = (1 << FT_TLV_EGR_IFINDEX)
FT_CMD_TRACE_CPU      = (1 << FT_TLV_CPU)
FT_CMD_TRACE_ING_TS   = (1 << FT_TLV_ING_TS)
FT_CMD_TRACE_EGR_TS   = (1 << FT_TLV_EGR_TS)
FT_CMD_PKT_CAPTURE    = (1 << FT_TLV_PKT_SNAPSHOT)
FT_CMD_DBG            = (1 << FT_TLV_DBG)

FT_CMD_TRACE_NODE    = (1 << FT_TLV_NODE)
FT_CMD_TRACE_LB_NODE    = (1 << FT_TLV_LB_NODE)
FT_CMD_TRACE_LB_BACK  = (1 << FT_TLV_LB_BACK)

FT_CMDS_MAP = {
    FT_CMD_TRACE_PKT_INFO : "FT_CMD_TRACE_PKT_INFO",
    FT_CMD_TRACE_IIFINDEX : "FT_CMD_TRACE_IIFINDEX",
    FT_CMD_TRACE_EIFINDEX : "FT_CMD_TRACE_EIFINDEX",
    FT_CMD_TRACE_CPU : "FT_CMD_TRACE_CPU",
    FT_CMD_TRACE_ING_TS : "FT_CMD_TRACE_ING_TS",
    FT_CMD_TRACE_EGR_TS : "FT_CMD_TRACE_EGR_TS",
    FT_CMD_PKT_CAPTURE : "FT_CMD_PKT_CAPTURE",
    FT_CMD_DBG : "FT_CMD_DBG",

    FT_CMD_TRACE_NODE : "FT_CMD_TRACE_NODE",
    FT_CMD_TRACE_LB_NODE : "FT_CMD_TRACE_LB_NODE",
    FT_CMD_TRACE_LB_BACK : "FT_CMD_TRACE_LB_BACK"
}

FT_CMDS_ALL = 0
for k in FT_CMDS_MAP: FT_CMDS_ALL |= k

# Flags
FT_TRUNCATED = (1 << 0)
FT_ERROR = (1 << 0)

FT_FLAGS_MAP = {
    FT_TRUNCATED: "FT_TRUNCATED",
    FT_ERROR: "FT_ERROR"
}

def tlv_dispatcher(raw_bytes, **kwargs):
    try:
        cls = Raw
        if len(raw_bytes) < 4:
            return cls
        next_type = int.from_bytes(raw_bytes[:4], byteorder='big')
        if next_type in FT_TLV_TYPE_MAP:
            cls = FT_TLV_TYPE_MAP.get(next_type, Raw)
        return cls(raw_bytes, **kwargs)
    except Exception as e:
        print(f"Error parsing: {e}")


class FlowTracer(Packet):
    name = "FlowTracer"
    fields_desc = [
        # struct ft_cmds
        FlagsField("cmds", 0, 32, FT_CMDS_MAP),
        StrFixedLenField("cmd_pad3", b"\x00"*12, length=12),

        # struct ft_hdr
        ShortField("l4_sport", 0),
        FlagsField("flags", 0, 8, FT_FLAGS_MAP),
        StrFixedLenField("pad1", b"\x00", length=1),
        FieldLenField("tlvs_len", None, length_of="tlvs", fmt="!I"),
        PacketListField("tlvs", [], tlv_dispatcher, length_from=lambda pkt: pkt.tlvs_len),
    ]

# Bind default port
default_port = 896
bind_layers(TCP, FlowTracer, sport=default_port)
bind_layers(UDP, FlowTracer, sport=default_port)
bind_layers(SCTP, FlowTracer, sport=default_port)

def autotest():
    # Make sure structs are correctly aligned
    assert len(FlowTracer()) == 24

    assert len(FlowTracerTLVBase()) == 12

    info_tlv = FlowTracerTLVInfo()
    assert len(info_tlv) == 36
    assert info_tlv.type == FT_TLV_PKT_INFO
    assert info_tlv.len == 36
    info2_tlv = FlowTracerTLVInfo(bytes(info_tlv))
    assert info2_tlv.type == FT_TLV_PKT_INFO
    assert info2_tlv.len == 36

    ingif_tlv = FlowTracerTLVIngIfindex()
    assert len(ingif_tlv) == 16
    assert ingif_tlv.type == FT_TLV_ING_IFINDEX
    assert ingif_tlv.len == 16

    egrif_tlv = FlowTracerTLVEgrIfindex()
    assert len(egrif_tlv) == 16
    assert egrif_tlv.type == FT_TLV_EGR_IFINDEX
    assert egrif_tlv.len == 16

    cpu_tlv = FlowTracerTLVCpu()
    assert len(cpu_tlv) == 16
    assert cpu_tlv.type == FT_TLV_CPU
    assert cpu_tlv.len == 16

    ingts_tlv = FlowTracerTLVIngTs()
    assert len(ingts_tlv) == 20
    assert ingts_tlv.type == FT_TLV_ING_TS
    assert ingts_tlv.len == 20

    egrts_tlv = FlowTracerTLVEgrTs()
    assert len(egrts_tlv) == 20
    assert egrts_tlv.type == FT_TLV_EGR_TS
    assert egrts_tlv.len == 20

    dbg_tlv = FlowTracerTLVDbg()
    assert len(dbg_tlv) == 12
    assert dbg_tlv.type == FT_TLV_DBG
    assert dbg_tlv.len == 12

    pktsnap_tlv = FlowTracerTLVPacketSnap()
    assert len(pktsnap_tlv) == 12
    assert pktsnap_tlv.type == FT_TLV_PKT_SNAPSHOT
    assert pktsnap_tlv.len == 12
    """
    #TODO fixme
    pktsnap_a_tlv = FlowTracerTLVPacketSnap(data=IP())
    pktsnap_b_tlv = FlowTracerTLVPacketSnap(bytes(pktsnap_a_tlv))
    pktsnap_a_tlv.show()
    pktsnap_b_tlv.show()
    hexdump(pktsnap_a_tlv)
    hexdump(pktsnap_b_tlv)

    assert pktsnap_a_tlv.len == 12 + 20
    assert len(bytes(pktsnap_a_tlv)) == 12 + 20
    assert pktsnap_b_tlv.len ==  12 + 20
    """

    node_tlv = FlowTracerTLVNode()
    assert len(node_tlv) == 20
    assert node_tlv.type == FT_TLV_NODE
    assert node_tlv.len == 20

    lbnode_tlv = FlowTracerTLVLBNode()
    assert len(lbnode_tlv) == 20
    assert lbnode_tlv.type == FT_TLV_LB_NODE
    assert lbnode_tlv.len == 20

    lbback_tlv = FlowTracerTLVLBBackend()
    assert len(lbback_tlv) == 20
    assert lbback_tlv.type == FT_TLV_LB_BACK
    assert lbback_tlv.len == 20

    # Make sure tlvs_len is properly calculated when stacking
    p = TCP() / FlowTracer(tlvs = [
        FlowTracerTLVIngIfindex()
    ])

    p = TCP(bytes(p))
    assert p["FlowTracer"].tlvs_len == 16

    tlv = p['FlowTracer'].tlvs[0]

    p = (
        FlowTracer(tlvs = [
            FlowTracerTLVIngTs(),
            FlowTracerTLVEgrTs(),
            FlowTracerTLVIngIfindex(),
            #FlowTracerTLVPacketSnap(data=IP()/TCP()) / TODO fixme
            FlowTracerTLVNode(),
            FlowTracerTLVLBNode(),
            FlowTracerTLVLBBackend()
        ]) /
        Raw(load=b'\x00' * 512)
    )

    p = FlowTracer(bytes(p))

    p2 = FlowTracer(bytes(p))
    assert len(p) == len(p2)

    tlvs_len = 20 + 20 + 16 + 20 + 20 + 20 #+ TODO add pkt snap(12 + 40)
    p["FlowTracer"].tlvs_len = tlvs_len #Note: scapy doesn't populate tlvs_len, not even after build()
    assert p == p2

    assert len(p) == (24 + tlvs_len + 512)
    assert p["FlowTracer"].tlvs_len == tlvs_len

    return True

assert autotest()
