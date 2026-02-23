# Using Scapy for BPF unit tests in Cilium

## How to port or write your first unit test with Scapy buffers

Start by looking at `tc_l2_announce.c` test as a reference, along with the
`scapy.h` header, and check commit [`6595a3cbe5`](https://github.com/cilium/cilium/commit/6595a3cbe5).

Steps:

0. Create the BPF unit test skeleton, if test is not there
1. Define the buffer you will use in a file `bpf/tests/scapy/<test_name>_pkt_defs.py`,
   following the format below:
```
## <Test name> (test_file_name.c)

<test_name>_<packet_name> = (
  Ether()/...
...
)
```
   Packet definitions are global, so make sure to prefix them with `test_name`.
2. In the `_pktgen` section of the test, declare the buffer using
   `BUF_DECL(LOCAL_NAME, <test_name>_<packet_name>)`, and then push the buffer
   bytes to the builder using `BUILDER_PUSH_BUF(builder, LOCAL_NAME)`.
3. On the `_check` functions, use `BUF_DECL()` to declare the buffer, and use
   `ASSERT_CTX_BUF_OFF("assert message", "<First Scapy Layer: e.g. Ether>", ctx
   offset, LOCAL_NAME, size to compare)`.
4. Remove old asserts.

### Porting an existing test

You can take as a reference commit [`6595a3cbe5`](https://github.com/cilium/cilium/commit/6595a3cbe5).

> [!IMPORTANT]
> To prevent regressions caused by two errors canceling each other out, do NOT
> remove existing assertions until packet generation _and_ all `ASSERT_CTX_*`
> checks pass.

#### Packet generation

Start by modifying the `_pktgen()` section (`build_packet()` in some tests). Use
`HEXDUMP()` to dump the pkt after `pktgen__finish()`:

<details>
<summary><i>diff: using hexdump()</i></summary>

```
diff --git a/bpf/tests/tc_l2_announcement6.c b/bpf/tests/tc_l2_announcement6.c
index 3f9303e46e..6193bf9200 100644
--- a/bpf/tests/tc_l2_announcement6.c
+++ b/bpf/tests/tc_l2_announcement6.c
@@ -16,6 +16,7 @@
 #undef QUIET_CT

 #include "pktgen.h"
+#include "../lib/hexdump.h"

 /* Enable code paths under test */
 #define ENABLE_IPV6
@@ -94,6 +95,7 @@ static __always_inline int build_packet(struct __ctx_buff *ctx)
                return TEST_ERROR;

        pktgen__finish(&builder);
+       HEXDUMP("test", ctx);
        return 0;
 }
```

</details>

Do a run `make run` and recover the trace:

```
~/dev/cilium/bpf/tests$ cat output/trace_pipe.log | grep test
[...]
           <...>-2084557 [003] b..11 146984.634298: bpf_trace_printk: tc_l2_announcement6.c:98 test: pkt_hex Ether[3333ff000001deadbeefdeef86dd6000000000203a4020010000000000000000000000000001fd1000000000000000000000000000018700000040000000fd1000000000000000000000000000010101deadbeefdeef]
```

Now open a Scapy shell, and use `command()` to create the scapy command:

```
>>> s = "3333ff000001deadbeefdeef86dd6000000000203a4020010000000000000000000000000001fd1000000000000000000000000000018700000040000000fd1000000000000000000000000000010101deadbeefdeef"
>>> p = Ether(bytes.fromhex(s))
>>> p.command()
"Ether(dst='33:33:ff:00:00:01', src='de:ad:be:ef:de:ef', type=34525)/IPv6(version=6, tc=0, fl=0, plen=32, nh=58, hlim=64, src='2001::1', dst='fd10::1')/ICMPv6ND_NS(type=135, code=0, cksum=0, res=1073741824, tgt='fd10::1')/ICMPv6NDOptSrcLLAddr(type=1, len=1, lladdr='de:ad:be:ef:de:ef')"
```

Remove all the unnecessary fields, especially the ones inferred by stacking
layers, irrelevant or reasonable defaults. Make sure TTL are adjusted (e.g. +1
in some cases).

Replace values with the constants defined in `pkt_defs.py` (e.g.MACs, IPs). Add
any new value necessary in `pkt_defs.py` (if common) or in your specific
`test_pkt_defs.py`:

```
l2_announce6_ns = (
    Ether(dst=l2_announce6_ns_mmac, src=mac_one) /
    IPv6(src=v6_ext_node_one, dst=l2_announce6_ns_ma, hlim=255) /
    ICMPv6ND_NS(tgt=v6_svc_one) /
    ICMPv6NDOptSrcLLAddr(lladdr=mac_one)
)
```

Run the test and adjust the scapy packet until it passes.

#### Checks

If the expected packet in the `_check` function is different than the injected,
define the new packet. You can take as reference the injected packet.

```
l2_announce6_na = (
    Ether(dst=mac_one, src=mac_two) /
    IPv6(src=v6_svc_one, dst=v6_ext_node_one, hlim=255) /
    ICMPv6ND_NA(R=0, S=1, O=1, tgt=v6_svc_one) /
    ICMPv6NDOptDstLLAddr(lladdr=mac_two)
)
```

Add the `ASSERT_CTX_BUF_*()` after the current assertions but before
`test_finish()`:

```
	BUF_DECL(L2_ANNOUNCE6_NA, l2_announce6_na);

	ASSERT_CTX_BUF_OFF("tc_l2announce2_entry_found_na",
			   "Ether", ctx,
			   sizeof(__u32), L2_ANNOUNCE6_NA,
			   sizeof(BUF(L2_ANNOUNCE6_NA)));
	test_finish();
```

Run the test and adjust the expected scapy packet until checks pass. Finally,
remove all the packet-related assertions covered by the Scapy:

<details>
<summary><i>diff: example of a ported _check() function</i></summary>

```
@@ -115,27 +88,14 @@ int l2_announcement_arp_no_entry_check(__maybe_unused const struct __ctx_buff *c

        status_code = data;

        /* The program should pass unknown ARP messages to the stack */
        assert(*status_code == TC_ACT_OK);

-       l2 = data + sizeof(__u32);
-       if ((void *)l2 + sizeof(struct ethhdr) > data_end)
-               test_fatal("l2 out of bounds");
-
-       l3 = data + sizeof(__u32) + sizeof(struct ethhdr);
-
-       if ((void *)l3 + sizeof(struct arphdreth) > data_end)
-               test_fatal("l3 out of bounds");
-
-       assert(memcmp(l2->h_source, (__u8 *)mac_one, ETH_ALEN) == 0);
-       assert(memcmp(l2->h_dest, (__u8 *)mac_bcast, ETH_ALEN) == 0);
-       assert(l3->ar_op == bpf_htons(ARPOP_REQUEST));
-       assert(l3->ar_sip == v4_ext_one);
-       assert(l3->ar_tip == v4_svc_one);
-       assert(memcmp(l3->ar_sha, (__u8 *)mac_one, ETH_ALEN) == 0);
-       assert(memcmp(l3->ar_tha, (__u8 *)mac_bcast, ETH_ALEN) == 0);
-
+       BUF_DECL(EXPECTED_ARP_REQ, l2_announce_arp_req);
+       ASSERT_CTX_BUF_OFF("arp_req_no_entry_untouched", "Ether", ctx,
+                          sizeof(__u32), EXPECTED_ARP_REQ,
+                          sizeof(BUF(EXPECTED_ARP_REQ)));
        test_finish();

```
</details>

## Using Scapy

### General Scapy references

Some useful pointers:

* Scapy [official docs](https://scapy.readthedocs.io/en/latest/)
* Source code in [Github](https://github.com/secdev/scapy), and specifically the
  [layers folder](https://github.com/secdev/scapy/tree/master/scapy/layers).

### Hands on tutorial

The easiest way to learn about Scapy layers is to use the `scapy` CLI, and its
introspection capabilities. There are multiple ways to do that. So...

```
$ scapy
>>>
```

#### Listing all Scapy commands

Use `lsc()`.

#### Listing all available layers

```
>>> ls()
AD_AND_OR  : None
AD_KDCIssued : None
AH         : AH
AKMSuite   : AKM suite
ARP        : ARP
ASN1P_INTEGER : None
ASN1P_OID  : None
ASN1P_PRIVSEQ : None
ASN1_Packet : None
ASN1_Packet : None
[...]
ZigBeeBeacon : ZigBee Beacon Payload
ZigbeeAppCommandPayload : Zigbee Application Layer Command Payload
ZigbeeAppDataPayload : Zigbee Application Layer Data Payload (General APS Frame Format)
ZigbeeAppDataPayloadStub : Zigbee Application Layer Data Payload for Inter-PAN Transmission
ZigbeeClusterLibrary : Zigbee Cluster Library (ZCL) Frame
ZigbeeDeviceProfile : Zigbee Device Profile (ZDP) Frame
ZigbeeNWK  : Zigbee Network Layer
ZigbeeNWKCommandPayload : Zigbee Network Layer Command Payload
ZigbeeNWKStub : Zigbee Network Layer for Inter-PAN Transmission
ZigbeeSecurityHeader : Zigbee Security Header
```

Note: some layers, like BGP, MPLS etc.. are in contrib and need to be imported
manually.

```
>>> p = BGP()
---------------------------------------------------------------------------
NameError                                 Traceback (most recent call last)
Cell In[1], line 1
----> 1 p = BGP()

NameError: name 'BGP' is not defined
>>> from scapy.contrib.bgp import *
WARNING: [bgp.py] use_2_bytes_asn: True
>>> p = BGP()
```

There is a more interactive layer listing using `explore()`.

#### Inspecting a particular layer and its fields

To list the field names, you can create a temporary layer object and use `show()`:

```
>>> TCP().show()
###[ TCP ]###
  sport     = ftp_data
  dport     = http
  seq       = 0
  ack       = 0
  dataofs   = None
  reserved  = 0
  flags     = S
  window    = 8192
  chksum    = None
  urgptr    = 0
  options   = ''
```

Or use `ls(TCP)` to get the field and the types:

```
>>> ls(TCP)
sport      : ShortEnumField                      = ('20')
dport      : ShortEnumField                      = ('80')
seq        : IntField                            = ('0')
ack        : IntField                            = ('0')
dataofs    : BitField  (4 bits)                  = ('None')
reserved   : BitField  (3 bits)                  = ('0')
flags      : FlagsField                          = ('<Flag 2 (S)>')
window     : ShortField                          = ('8192')
chksum     : XShortField                         = ('None')
urgptr     : ShortField                          = ('0')
options    : TCPOptionsField                     = ("b''")
```

For fields such as enums you can check the valid options using:

```
IP().get_field('proto').i2s

{0: 'hopopt',
 1: 'icmp',
 2: 'igmp',
 3: 'ggp',
 4: 'ipencap',
 5: 'st',
 6: 'tcp',
 8: 'egp',
 9: 'igp',
 12: 'pup',
 17: 'udp',
 [...]
 143: 'ethernet',
 262: 'mptcp'}

```

For fields such as flags:

```
>>> IP().get_field('flags').names
['MF', 'DF', 'evil']
>>> TCP().get_field('flags').names
'FSRPAUECN'
```

#### Importing packets from a PCAP file

```
>>> pkts = rdpcap("test.pcap")
>>> len(pkts)
7
>>> pkts[0]
<Ether  dst=ff:ff:ff:ff:ff:ff src=de:ad:be:ef:de:ef type=ARP |<ARP  hwtype=Ethernet (10Mb) ptype=IPv4 hwlen=6 plen=4 op=who-has hwsrc=de:ad:be:ef:de:ef psrc=110.0.11.1 hwdst=ff:ff:ff:ff:ff:ff pdst=172.16.10.1 |>>
```

You can write a pcap file using `wrpcap("test_copy.pcap", pkts)`.

#### Creating scapy objects/packets from hex strings

Creating a scapy object from a hex string:

```
>>> s = "0013d4c3b2a1000c294f8d2c080045000034a6f400004006b1e6c0a80001c0a800c7c0a80050c0a80051aabbccdd11223344"
>>> p = Ether(bytes.fromhex(s))
>>> p.show()
###[ Ethernet ]###
  dst       = 00:13:d4:c3:b2:a1
  src       = 00:0c:29:4f:8d:2c
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 52
     id        = 42740
     flags     =
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0xb1e6
     src       = 192.168.0.1
     dst       = 192.168.0.199
     \options   \
###[ TCP ]###
        sport     = 49320
        dport     = http
        seq       = 3232235601
        ack       = 2864434397
        dataofs   = 1
        reserved  = 0
        flags     = SUN
        window    = 13124
        chksum    = None
        urgptr    = 0
        options   = ''

```

Dump in tcpdump-like hexdump representation:

```
>>> hexdump(p)
0000  FF FF FF FF FF FF 00 00 00 00 00 00 08 00 45 00  ..............E.
0010  00 33 00 01 00 00 40 06 7C C2 7F 00 00 01 7F 00  .3....@.|.......
0020  00 01 00 14 00 50 00 00 00 00 00 00 00 00 50 02  .....P........P.
0030  20 00 1F A3 00 00 48 65 6C 6C 6F 20 77 6F 72 6C   .....Hello worl
0040  64
```

C-style Byte array hex representation:

```
>>> p = Ether()/IP()/TCP()/Raw("Hello world")
>>> chexdump(p)
0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x33, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x7c, 0xc2, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x14, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00, 0x1f, 0xa3, 0x00, 0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64
```

#### Modifying a Scapy object, cloning, comparing.

```
>>> p = pkts[0] #Reference
>>> p2 = p.copy()
>>> p1["Ether"]
<Ether  dst=ff:ff:ff:ff:ff:ff src=de:ad:be:ef:de:ef type=ARP |<ARP  hwtype=Ethernet (10Mb) ptype=IPv4 hwlen=6 plen=4 op=who-has hwsrc=de:ad:be:ef:de:ef psrc=110.0.11.1 hwdst=ff:ff:ff:ff:ff:ff pdst=172.16.10.1 |>>
>>> p1["Ether"].dst = "AA:BB:CC:DD:EE:FF"
>>> p1 == p2
False
>>> p1["ARP"] == p2["ARP"]
True
```

#### Getting the Scapy "command" (stacked layer definition) from a Scapy object

Use `command()` on a Scapy object:

```
>>> pkts[0].command()
"Ether(dst='ff:ff:ff:ff:ff:ff', src='de:ad:be:ef:de:ef', type=2054)/ARP(hwtype=1, ptype=2048, hwlen=6, plen=4, op=1, hwsrc='de:ad:be:ef:de:ef', psrc='110.0.11.1', hwdst='ff:ff:ff:ff:ff:ff', pdst='172.16.10.1')"
```

#### Working with checksums

On a newly created Scapy object, checksums won't be computed and they will be
`None`. This is to allow further modification of the layers without having to
continously recalculate checksums.

```
>>> p = Ether()/IP()/TCP()/Raw("Hello world")
>>> p.show()
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:00:00:00:00:00
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     =
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = None  # <------------------
     src       = 127.0.0.1
     dst       = 127.0.0.1
     \options   \
###[ TCP ]###
        sport     = ftp_data
        dport     = http
        seq       = 0
        ack       = 0
        dataofs   = None
        reserved  = 0
        flags     = S
        window    = 8192
        chksum    = None  # <------------------
        urgptr    = 0
        options   = ''
###[ Raw ]###
           load      = 'Hello world'
```

_If not manually set_, Scapy will automatically compute the (right) checksum
when sending it, either via `send()` or `sendp()`. You can also force checksum
calculation using `show2()`.

```
>>> p.show2()
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:00:00:00:00:00
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 51
     id        = 1
     flags     =
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0x7cc2
     src       = 127.0.0.1
     dst       = 127.0.0.1
     \options   \
###[ TCP ]###
        sport     = ftp_data
        dport     = http
        seq       = 0
        ack       = 0
        dataofs   = 5
        reserved  = 0
        flags     = S
        window    = 8192
        chksum    = 0x1fa3
        urgptr    = 0
        options   = []
###[ Raw ]###
           load      = 'Hello world'
```

You can easily check whether a checksum is correct (e.g. when importing from
a PCAP capture) by copying it and using `show2()`:

<details>
<summary><i>Simple process to verify checksums</i></summary>

```
>>> p = Ether()/IP()/TCP()/Raw("Hello world") #this could come from a PCAP, hexdump() etc.
>>> p.show2()
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:00:00:00:00:00
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 51
     id        = 1
     flags     =
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0x7cc2
     src       = 127.0.0.1
     dst       = 127.0.0.1
     \options   \
###[ TCP ]###
        sport     = ftp_data
        dport     = http
        seq       = 0
        ack       = 0
        dataofs   = 5
        reserved  = 0
        flags     = S
        window    = 8192
        chksum    = 0x1fa3
        urgptr    = 0
        options   = []
###[ Raw ]###
           load      = 'Hello world'

>>> p["IP"].chksum = 1234 # Set it to an incorrect value
>>> p.show()
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:00:00:00:00:00
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = None
     tos       = 0x0
     len       = None
     id        = 1
     flags     =
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0x4d2
     src       = 127.0.0.1
     dst       = 127.0.0.1
     \options   \
###[ TCP ]###
        sport     = ftp_data
        dport     = http
        seq       = 0
        ack       = 0
        dataofs   = None
        reserved  = 0
        flags     = S
        window    = 8192
        chksum    = None
        urgptr    = 0
        options   = ''
###[ Raw ]###
           load      = 'Hello world'

>>> p_ok = p.copy()
>>> p_ok.show2()
###[ Ethernet ]###
  dst       = ff:ff:ff:ff:ff:ff
  src       = 00:00:00:00:00:00
  type      = IPv4
###[ IP ]###
     version   = 4
     ihl       = 5
     tos       = 0x0
     len       = 51
     id        = 1
     flags     =
     frag      = 0
     ttl       = 64
     proto     = tcp
     chksum    = 0x4d2
     src       = 127.0.0.1
     dst       = 127.0.0.1
     \options   \
###[ TCP ]###
        sport     = ftp_data
        dport     = http
        seq       = 0
        ack       = 0
        dataofs   = 5
        reserved  = 0
        flags     = S
        window    = 8192
        chksum    = 0x1fa3
        urgptr    = 0
        options   = []
###[ Raw ]###
           load      = 'Hello world'

>>> p == p2
False
```

</details>

#### Using ranges and sets for values

You can define a collection of packets with permutations on one or more fields
by using the set `[]` or the range `()` operators.

Use `list()` to generate all the permutations packets:

```
>>> meta_pkt = Ether()/IP(src=["1.1.1.1", "1.1.1.2"])/TCP()/Raw("Hello world")
>>> list(meta_pkt)
[<Ether  type=IPv4 |<IP  frag=0 proto=tcp src=1.1.1.1 |<TCP  |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp src=1.1.1.2 |<TCP  |<Raw  load='Hello world' |>>>>]
>>> meta_pkt2=Ether()/IP()/TCP(dport=(123,140))/Raw("Hello world")
>>> list(meta_pkt2)
[<Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=123 |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=124 |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=125 |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=126 |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=127 |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=128 |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=129 |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=130 |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=131 |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=132 |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=133 |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=134 |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=epmap |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=136 |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=137 |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=138 |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=netbios_ssn |<Raw  load='Hello world' |>>>>,
 <Ether  type=IPv4 |<IP  frag=0 proto=tcp |<TCP  dport=140 |<Raw  load='Hello world' |>>>>]
```

You can also directly inject them using `send()`/`sendp()` without the need to
use `list()`.
