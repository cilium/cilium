Cilium Warnings
###############

..
   NOTES: each warning has an id (e.g., cgrouplowproccount) used in the code to
   refer to specifics in this document. Code points to the latest version of the
   docs, so text should be valid for all supported Cilium versions.

.. _cgrouplowproccount:

Low cgroup process count
------------------------

For :ref:`host-services`, Cilium attaches eBPF programs at cgroup hooks. For
this to work properly, the cgroup that the programs are attached to needs to be
at the proper level in the cgroup hierarchy so that all pods are created under
it.

The above warning indicates that something might be wrong since there is only
one process running on the cgroup that the programs will be attached.  This, for
example, might happen if the cilium pod runs on its own cgroup.

For some environments (e.g., Kind) Cilium will try to avoid this issue by
figuring out the proper path.

You can provide an appropriate cgroup path to the agent via the
``--cgroup-root`` option.

Additional info
***************

* `Control Group v2 documentation <https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html>`_
* ``bpftool cgroup tree`` provides an overview of the bpf cgroup-attached programs
