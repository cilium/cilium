# Copyright Authors of Cilium
# SPDX-License-Identifier: Apache-2.0

from scapy.all import *

from pkt_defs_common import *

# Test packet/buffer definitions
from selftest_pkt_defs import *
from ipv6_ndp_pkt_defs import *
from tc_l2_announce_pkt_defs import *
from tc_l2_announce6_pkt_defs import *
from wg_from_netdev_pkt_defs import *
from tc_wireguard_from_overlay_pkt_defs import *
from icmp_err_revnat_pkt_defs import *
