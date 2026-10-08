.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

eBPF Program Types
==================

Cilium uses the following eBPF program types to attach programs to the kernel:

- ``BPF_PROG_TYPE_XDP``
- ``BPF_PROG_TYPE_SCHED_ACT``
- ``BPF_PROG_TYPE_CGROUP_SOCK_ADDR``
