.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bpf_guide:

***************************
BPF and XDP Reference Guide
***************************

.. note:: This documentation section is targeted at developers and users who
          want to understand BPF and XDP in great technical depth. While
          reading this reference guide may help broaden your understanding of
          Cilium, it is not a requirement to use Cilium. Please refer to the
          :ref:`getting_started` guide and :ref:`ebpf_datapath` for a higher
          level introduction.

BPF is a highly flexible and efficient virtual machine-like construct in the
Linux kernel allowing to execute bytecode at various hook points in a safe
manner. It is used in a number of Linux kernel subsystems, most prominently
networking, tracing and security (e.g. sandboxing).

Although BPF exists since 1992, this document covers the extended Berkeley
Packet Filter (eBPF) version which has first appeared in Kernel 3.18 and
renders the original version which is being referred to as "classic" BPF
(cBPF) these days mostly obsolete. cBPF is known to many as being the packet
filter language used by tcpdump. Nowadays, the Linux kernel runs eBPF only and
loaded cBPF bytecode is transparently translated into an eBPF representation
in the kernel before program execution. This documentation will generally refer
to the term BPF unless explicit differences between eBPF and cBPF are being
pointed out.

Even though the name Berkeley Packet Filter hints at a packet filtering specific
purpose, the instruction set is generic and flexible enough these days that
there are many use cases for BPF apart from networking. See :ref:`bpf_users`
for a list of projects which use BPF.

Cilium uses BPF heavily in its data path, see :ref:`ebpf_datapath` for further
information. The goal of this chapter is to provide a BPF reference guide in
order to gain understanding of BPF, its networking specific use including loading
BPF programs with tc (traffic control) and XDP (eXpress Data Path), and to aid
with developing Cilium's BPF templates.

.. toctree::
   :maxdepth: 2

   architecture
   toolchain
   debug_and_test
   progtypes
   resources
