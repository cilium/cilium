# Using Scapy for BPF unit tests in Cilium

## How to port or write your first unit test with Scapy buffers

Start by looking at the `tc_l2_announce.c` test as a reference, along with the
`scapy.h` header. Use `git blame` to find the commit that ported it to Scapy.

Steps:

0. Create a regular BPF unit test, if not there
1. Define the buffer you will use in the section "Test buffer definitions"
   within `bpf/tests/scapy/pkt_defs.py`, following the format below
```
## <Test name>

<test_name>_<packet_name> = Ether()/...
...
```
2. In the `_pktgen` section that needs to use the Scapy buffer, declare the
   buffer using `BUF_DECL(LOCAL_NAME, <test_name>_<packet_name>)`. You can then
   push the buffer bytes to the builder using
   `BUILDER_PUSH_BUF(builder, LOCAL_NAME)`.
3. On the `_check` functions use `BUF_DECL()` to declare the buffer, and use
   `ASSERT_CTX_BUF_OFF("assert message", "<First Scapy Layer: e.g. Ether>", ctx
   offset, LOCAL_NAME, size to compare)`.

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

```
>>> p = Ether()/IP()/TCP()/Raw("Hello world")
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

#### Using ranges and sets for values

You can define a collection of packets with permutations on one or more fields
using the set `[]` or the range `()` operators.

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
