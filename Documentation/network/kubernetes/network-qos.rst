.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _network-qos:

*******************
Network QoS (alpha)
*******************

Cilium's Networking Quality of Service (QoS) feature allows for better control over network bandwidth
usage when a node is under network contention. QoS allows for classifying traffic from pods on a given node 
into different priority levels Guaranteed, Burstable, or BestEffort (think high, medium, low). Currently, this feature relies on
Cilium Bandwidth Manager for the qdisc setup, so enabling BW Manager is a prerequisite . This feature 
relies on Linux kernel's Fair Queueing (FQ) qdisc to enforce priority levels. Kernel 6.7 or later is required.

FQ implements a weighted round robin algorithm for dequeuing packets. The default weights are
589824, 196608 and 65536 for QoS classes Guaranteed, Burstable, and BestEffort respectively 
which gives us a ratio of 9:3:1. Priority levels can be configured by annotatiting pods with
`bandwidth.cilium.io/priority`. Supported strings are `guaranteed`, `burstable` and `bestEffort`. 

Under contention if a low priority pod contends with a high priority pod, bandwidth would be split in ~9:1 ratio.
~3:1 for high to medium.

Requirements
############

* Bandwidth Manager needs to enabled
* Linux Kernel 6.7+

Testing
#######

Newer versions of iproute2 display priority class / band level metrics. FQ refers to bands 
high, medium and low as 0, 1 and 2.

.. code-block:: shell-session

    $ tc -s qdisc show | grep flows

        flows 2585 (inactive 2537 throttled 0) band0_pkts 30 band1_pkts 0 band2_pkts 61
        flows 2571 (inactive 2556 throttled 4) band0_pkts 12 band1_pkts 0 band2_pkts 15 next_packet_delay 105us
        flows 2373 (inactive 2318 throttled 0) band0_pkts 40 band1_pkts 0 band2_pkts 63
        flows 2617 (inactive 2588 throttled 8) band0_pkts 13 band1_pkts 0 band2_pkts 41 next_packet_delay 59.5us


Limitations
###########

* Currently this feature has been tested successfully only on instances with single TX queue network cards. See issue #<TODO> for more details.
* Quality of Service applies only to egress traffic.
