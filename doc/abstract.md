Cilium - Fast IPv6-only networking for containers based on BPF and XDP

Cilium provides IPv6 networking for Linux containers by generating programs for
each individual container on the fly and then run them as JITed BPF code in
the kernel. By generating and compiling the code on the fly, the program is
reduced to the minimally required feature set and then heavily optimized by the
compiler as parameters become plain variables. The upcoming addition of the
Express Data Plane (XDP) will make this approach even more efficient as the
programs will get invoked directly from the network driver. We should be able
to achieve similar performance number as demonstrated by kernel bypassing
methods without ever leaving the context of the kernel.

Using BPF, we have implemented a full IPv6 routing data plane with identifier/
locator addressing logic, a connection tracker tailored to containers which
is significantly faster than Netfilter and NAT46 translation logic to provide
connectivity to legacy IPv4 endpoints. It also includes a highly scalable
policy enforcement engine based on container labels, thus decoupled from the
network topology.

This talk will provide an introduction to the model and explain further
possibilities such as the option to implement DRS from the host or the
integration with the perf ring buffer for very fast packet sampling of
production workloads. The talk will be concluded with a demo of the
implemented functionality.
