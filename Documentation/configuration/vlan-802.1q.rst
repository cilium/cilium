.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _vlan_802.1q:

*******************
VLAN 802.1q support
*******************

Cilium enables firewalling on native devices in use and will filter all unknown traffic. VLAN 802.1q packets
will always be passed through their main device with associated tag (e.g. VLAN device is ``eth0.4000`` and its main interface is ``eth0``).
By default, Cilium will allow all tags from the native devices (i.e. if ``eth0.4000`` is controlled by Cilium and has
an eBPF program attached, then VLAN tag ``4000`` will be allowed on device ``eth0``). Additional VLAN tags may be allowed
with the cilium-agent flag ``--vlan-bpf-bypass=4001,4002`` (or Helm variable ``--set bpf.vlanBypass="{4001,4002}"``).

The list of allowed VLAN tags cannot be too big in order to keep eBPF program of predictable size. Currently this list
should contain no more than 5 entries. If you need more, then there is only one way for now: you need to allow
all tags with cilium-agent flag ``--vlan-bpf-bypass=0``.

.. note::

    Currently, the cilium-agent will scan for available VLAN devices and tags only on startup.
