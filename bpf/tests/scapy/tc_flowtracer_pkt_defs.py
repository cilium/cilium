from pkt_defs import *
from flowtracer_hdr import *

ee_tc_ft_sentinel = (
    Ether(dst=mac_one, src=mac_two) /
    IP(src=v4_ext_one, dst=v4_svc_one) /
    TCP(dport=80) /
    FlowTracer(cmds = FT_CMDS_ALL, l4_sport=64000) /
    Raw(b'\00'*512)
)

ee_tc_ft_sentinel_intercepted = ee_tc_ft_sentinel.copy()
ee_tc_ft_sentinel_intercepted["TCP"].sport = 64000
ee_tc_ft_sentinel_intercepted["FlowTracer"].l4_sport = 896

assert(ee_tc_ft_sentinel["TCP"].sport == 896)
assert(ee_tc_ft_sentinel_intercepted["TCP"].sport == 64000)

# Note packet modifications are done without touching L4 csum (deferred)
# So here we set the L4 csum to the original packet's L4 csum
ee_tc_ft_sentinel = Ether(bytes(ee_tc_ft_sentinel))

ee_tc_ft_traces32 = (
    Ether(dst=mac_one, src=mac_two) /
    IP(src=v4_ext_one, dst=v4_svc_one) /
    TCP(dport=80, sport=64000, chksum=ee_tc_ft_sentinel["TCP"].chksum) /
    FlowTracer(cmds = FT_CMDS_ALL, l4_sport=896, tlvs= [
        FlowTracerTLVIngIfindex(tracepoint=0x16E55, ifindex=1),
        FlowTracerTLVEgrIfindex(tracepoint=0xE6E55, ifindex=2),
        FlowTracerTLVCpu(tracepoint=0xC06E, cpu=2)
    ]) /
    Raw(b'\00'*464)
)

ee_tc_ft_traces3264 = (
    Ether(dst=mac_one, src=mac_two) /
    IP(src=v4_ext_one, dst=v4_svc_one) /
    TCP(dport=80, sport=64000, chksum=ee_tc_ft_sentinel["TCP"].chksum) /
    FlowTracer(cmds = FT_CMDS_ALL, l4_sport=896, tlvs= [
        FlowTracerTLVIngIfindex(tracepoint=0x16E55, ifindex=1),
        FlowTracerTLVEgrIfindex(tracepoint=0xE6E55, ifindex=2),
        FlowTracerTLVCpu(tracepoint=0xC06E, cpu=2),
        FlowTracerTLVIngTs(tracepoint=0x16E55, ts=0x1234),
        FlowTracerTLVEgrTs(tracepoint=0xE6E55, ts=0x4321),
        FlowTracerTLVNode(tracepoint=0xE6E55, node=0x1B00F1),
        FlowTracerTLVLBNode(tracepoint=0xE6E55, node=0x1B00F2),
        FlowTracerTLVLBBackend(tracepoint=0xE6E55, backend=0x1B00BE)
    ]) /
    Raw(b'\00'*364)
)
ee_tc_ft_traces3264_csum = ee_tc_ft_traces3264.copy()
ee_tc_ft_traces3264_csum["TCP"].chksum = None
