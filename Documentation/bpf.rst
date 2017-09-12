.. _bpf_guide:

***************************
BPF and XDP Reference Guide
***************************

.. note:: This documentation section is targeted at developers and users who
          want to understand BPF and XDP in great technical depth. While
          reading this reference guide may help broaden your understanding of
          Cilium, it is not a requirement to use Cilium. Please refer to the
          :ref:`gs_guide` and :ref:`arch_guide` for a higher level
          introduction.

BPF is a highly flexible and efficient virtual machine-like construct in the
Linux kernel allowing to execute bytecode at various hook points in a safe
manner. It is used in a number of Linux kernel subsystems, most prominently
networking, tracing and security (e.g. sandboxing).

Although BPF exists since 1992, this document covers the extended Berkley
Packet Filter (eBPF) version which has first appeared in Kernel 3.18 and
renders the original version which is being referred to as "classic" BPF
(cBPF) these days mostly obsolete. cBPF is known to many as being the packet
filter language used by tcpdump. Nowadays, the Linux kernel runs eBPF only and
loaded cBPF bytecode is transparently translated into an eBPF representation
in the kernel before program execution. This documentation will generally refer
to the term BPF unless explicit differences between eBPF and cBPF are being
pointed out.

Even though the name Berkley Packet Filter hints at a packet filtering specific
purpose, the instruction set is generic and flexible enough these days that
there are many use cases for BPF apart from networking. See :ref:`bpf_users`
for a list of projects which use BPF.

Cilium uses BPF heavily in its data path, see :ref:`arch_guide` for further
information. The goal of this chapter is to provide a BPF reference guide in
oder to gain understanding of BPF, its networking specific use including loading
BPF programs with tc (traffic control) and XDP (eXpress Data Path), and to aid
with developing Cilium's BPF templates.

BPF Architecture
================

BPF does not define itself by only providing its instruction set, but also by
offering further infrastructure around it such as maps which act as efficient
key / value stores, helper functions to interact with and leverage kernel
functionality, tail calls for calling into other BPF programs, security
hardening primitives, a pseudo file system for pinning objects (maps,
programs), and infrastructure for allowing BPF to be offloaded, for example, to
a network card.

LLVM provides a BPF back end, so that tools like clang can be used to
compile C into a BPF object file, which can then be loaded into the kernel.
BPF is deeply tied to the Linux kernel and allows for full programmability
without sacrificing native kernel performance.

Last but not least, also the kernel subsystems making use of BPF are part of
BPF's infrastructure. The two main subsystems discussed throughout this
document are tc and XDP where BPF programs can be attached to. XDP BPF programs
are attached at the earliest networking driver stage and trigger a run of the
BPF program upon packet reception. By definition, this achieves the best
possible packet processing performance since packets cannot get processed at an
even earlier point in software. However, since this processing occurs so early
in the networking stack, the stack has not yet extracted metadata out of the
packet. On the other hand, tc BPF programs are executed later in the kernel
stack, so they have access to more metadata and core kernel functionality.
Apart from tc and XDP programs, there are various other kernel subsystems as
well which use BPF such as tracing (kprobes, uprobes, tracepoints, etc).

The following subsections provide further details on individual aspects of the
BPF architecture.

Instruction Set
---------------

BPF is a general purpose RISC instruction set and was originally designed for the
purpose of writing programs in a subset of C which can be compiled into BPF instructions
through a compiler back end (e.g. LLVM), so that the kernel can later on map them
through an in-kernel JIT compiler into native opcodes for optimal execution performance
inside the kernel.

The advantages for pushing these instructions into the kernel include:

* Making the kernel programmable without having to cross kernel / user space
  boundaries. For example, BPF programs related to networking, as in the case of
  Cilium, can implement flexible container policies, load balancing and other means
  without having to move packets to user space and back into the kernel. State
  between BPF programs and kernel / user space can still be shared through maps
  whenever needed.

* Given the flexibility of a programmable data path, programs can be heavily optimized
  for performance also by compiling out features that are not required for the use cases
  the program solves. For example, if a container does not require IPv4, then the BPF
  program can be built to only deal with IPv6 in order to save resources in the fast-path.

* In case of networking (e.g. tc and XDP), BPF programs can be updated atomically
  without having to restart the kernel, system services or containers, and without
  traffic interruptions. Furthermore, any program state can also be maintained
  throughout updates via BPF maps.

* BPF provides a stable ABI towards user space, and does not require any third party
  kernel modules. BPF is a core part of the Linux kernel that is shipped everywhere,
  and guarantees that existing BPF programs keep running with newer kernel versions.
  This guarantee is the same guarantee that the kernel provides for system calls with
  regard to user space applications.

* BPF programs work in concert with the kernel, they make use of existing kernel
  infrastructure (e.g. drivers, netdevices, tunnels, protocol stack, sockets) and
  tooling (e.g. iproute2) as well as the safety guarantees which the kernel provides.
  Unlike kernel modules, BPF programs are verified through an in-kernel verifier in
  order to ensure that they cannot crash the kernel, always terminate, etc. XDP
  programs, for example, reuse the existing in-kernel drivers and operate on the
  provided DMA buffers containing the packet frames without exposing them or an entire
  driver to user space as in other models. Moreover, XDP programs reuse the existing
  stack instead of bypassing it. BPF can be considered a generic "glue code" to
  kernel facilities for crafting programs to solve specific use cases.

The execution of a BPF program inside the kernel is always event driven! For example,
a networking device which has a BPF program attached on its ingress path will trigger
the execution of the program once a packet is received, a kernel address which has a
kprobes with a BPF program attached will trap once the code at that address gets
executed, then invoke the kprobes callback function for instrumentation which
subsequently triggers the execution of the BPF program attached to it.

BPF consists of eleven 64 bit registers with 32 bit subregisters, a program counter
and a 512 byte large BPF stack space. Registers are named ``r0`` - ``r10``. The
operating mode is 64 bit by default, the 32 bit subregisters can only be accessed
through special ALU (arithmetic logic unit) operations. The 32 bit lower subregisters
zero-extend into 64 bit when they are being written to.

Register ``r10`` is the only register which is read-only and contains the frame pointer
address in order to access the BPF stack space. The remaining ``r0`` - ``r9``
registers are general purpose and of read/write nature.

A BPF program can call into a predefined helper function, which is defined by
the core kernel (never by modules). The BPF calling convention is defined as
follows:

* ``r0`` contains the return value of a helper function call.
* ``r1`` - ``r5`` hold arguments from the BPF program to the kernel helper function.
* ``r6`` - ``r9`` are callee saved registers that will be preserved on helper function call.

The BPF calling convention is generic enough to map directly to ``x86_64``, ``arm64``
and other ABIs, thus all BPF registers map one to one to HW CPU registers, so that a
JIT only needs to issue a call instruction, but no additional extra moves for placing
function arguments. This calling convention was modeled to cover common call
situations without having a performance penalty. Calls with 6 or more arguments
are currently not supported. The helper functions in the kernel which are dedicated
to BPF (``BPF_CALL_0()`` to ``BPF_CALL_5()`` functions) are specifically designed
with this convention in mind.

Register ``r0`` is also the register containing the exit value for the BPF program.
The semantics of the exit value are defined by the type of program. Furthermore, when
handing execution back to the kernel, the exit value is passed as a 32 bit value.

Registers ``r1`` - ``r5`` are scratch registers, meaning the BPF program needs to
either spill them to the BPF stack or move them to callee saved registers if these
arguments are to be reused across multiple helper function calls. Spilling means
that the variable in the register is moved to the BPF stack. The reverse operation
of moving the variable from the BPF stack to the register is called filling. The
reason for spilling/filling is due to the limited number of registers.

Upon entering execution of a BPF program, register ``r1`` initially contains the
context for the program. The context is the input argument for the program (similar
to ``argc/argv`` pair for a typical C program). BPF is restricted to work on a single
context. The context is defined by the program type, for example, a networking
program can have a kernel representation of the network packet (``skb``) as the
input argument.

The general operation of BPF is 64 bit to follow the natural model of 64 bit
architectures in order to perform pointer arithmetics, pass pointers but also pass 64
bit values into helper functions, and to allow for 64 bit atomic operations.

The maximum instruction limit per program is restricted to 4096 BPF instructions,
which, by design, means that any program will terminate quickly. Although the
instruction set contains forward as well as backward jumps, the in-kernel BPF
verifier will forbid loops so that termination is always guaranteed. Since BPF
programs run inside the kernel, the verifier's job is to make sure that these are
safe to run, not affecting the system's stability. This means that from an instruction
set point of view, loops can be implemented, but the verifier will restrict that.
However, there is also a concept of tail calls that allows for one BPF program to
jump into another one. This, too, comes with an upper nesting limit of 32 calls,
and is usually used to decouple parts of the program logic, for example, into stages.

The instruction format is modeled as two operand instructions, which helps mapping
BPF instructions to native instructions during JIT phase. The instruction set is
of fixed size, meaning every instruction has 64 bit encoding. Currently, 87 instructions
have been implemented and the encoding also allows to extend the set with further
instructions when needed. The instruction encoding of a single 64 bit instruction is
defined as a bit sequence from most significant bit (MSB) to least significant bit (LSB)
of ``op:8``, ``dst_reg:4``, ``src_reg:4``, ``off:16``, ``imm:32``. ``off`` and
``imm`` is of signed type. The encodings are part of the kernel headers and
defined in ``linux/bpf.h`` header, which also includes ``linux/bpf_common.h``.

``op`` defines the actual operation to be performed. Most of the encoding for ``op``
has been reused from cBPF. The operation can be based on register or immediate
operands. The encoding of ``op`` itself provides information on which mode to use
(``BPF_X`` for denoting register-based operations, and ``BPF_K`` for immediate-based
operations respectively). In the latter case, the destination operand is always
a register. Both ``dst_reg`` and ``src_reg`` provide additional information about
the register operands to be used (e.g. ``r0`` - ``r9``) for the operation. ``off``
is used in some instructions to provide a relative offset, for example, for addressing
the stack or other buffers available to BPF (e.g. map values, packet data, etc),
or jump targets in jump instructions. ``imm`` contains a constant / immediate value.

The available ``op`` instructions can be categorized into various instruction
classes. These classes are also encoded inside the ``op`` field. The ``op`` field
is divided into (from MSB to LSB) ``code:4``, ``source:1`` and ``class:3``. ``class``
is the more generic instruction class, ``code`` denotes a specific operational
code inside that class, and ``source`` tells whether the source operand is a register
or an immediate value. Possible instruction classes include:

* ``BPF_LD``, ``BPF_LDX``: Both classes are for load operations. ``BPF_LD`` is
  used for loading a double word as a special instruction spanning two instructions
  due to the ``imm:32`` split, and for byte / half-word / word loads of packet data.
  The latter was carried over from cBPF mainly in order to keep cBPF to BPF
  translations efficient, since they have optimized JIT code. For native BPF
  these packet load instructions are less relevant nowadays. ``BPF_LDX`` class
  holds instructions for byte / half-word / word / double-word loads out of
  memory. Memory in this context is generic and could be stack memory, map value
  data, packet data, etc.

* ``BPF_ST``, ``BPF_STX``: Both classes are for store operations. Similar to ``BPF_LDX``
  the ``BPF_STX`` is the store counterpart and is used to store the data from a
  register into memory, which, again, can be stack memory, map value, packet data,
  etc. ``BPF_STX`` also holds special instructions for performing word and double-word
  based atomic add operations, which can be used for counters, for example. The
  ``BPF_ST`` class is similar to ``BPF_STX`` by providing instructions for storing
  data into memory only that the source operand is an immediate value.

* ``BPF_ALU``, ``BPF_ALU64``: Both classes contain ALU operations. Generally,
  ``BPF_ALU`` operations are in 32 bit mode and ``BPF_ALU64`` in 64 bit mode.
  Both ALU classes have basic operations with source operand which is register-based
  and an immediate-based counterpart. Supported by both are add (``+``), sub (``-``),
  and (``&``), or (``|``), left shift (``<<``), right shift (``>>``), xor (``^``),
  mul (``*``), div (``/``), mod (``%``), neg (``~``) operations. Also mov (``<X> := <Y>``)
  was added as a special ALU operation for both classes in both operand modes.
  ``BPF_ALU64`` also contains a signed right shift. ``BPF_ALU`` additionally
  contains endianness conversion instructions for half-word / word / double-word
  on a given source register.

* ``BPF_JMP``: This class is dedicated to jump operations. Jumps can be unconditional
  and conditional. Unconditional jumps simply move the program counter forward, so
  that the next instruction to be executed relative to the current instruction is
  ``off + 1``, where ``off`` is the constant offset encoded in the instruction. Since
  ``off`` is signed, the jump can also be performed backwards as long as it does not
  create a loop and is within program bounds. Conditional jumps operate on both,
  register-based and immediate-based source operands. If the condition in the jump
  operations results in ``true``, then a relative jump to ``off + 1`` is performed,
  otherwise the next instruction (``0 + 1``) is performed. This fall-through
  jump logic differs compared to cBPF and allows for better branch prediction as it
  fits the CPU branch predictor logic more naturally. Available conditions are
  jeq (``==``), jne (``!=``), jgt (``>``), jge (``>=``), jsgt (signed ``>``), jsge
  (signed ``>=``), jlt (``<``), jle (``<=``), jslt (signed ``<``), jsle (signed
  ``<=``) and jset (jump if ``DST & SRC``). Apart from that, there are three
  special jump operations within this class: the exit instruction which will leave
  the BPF program and return the current value in ``r0`` as a return code, the call
  instruction, which will issue a function call into one of the available BPF helper
  functions, and a hidden tail call instruction, which will jump into a different
  BPF program.

The Linux kernel is shipped with a BPF interpreter which executes programs assembled in
BPF instructions. Even cBPF programs are translated into eBPF programs transparently
in the kernel, except for architectures that still ship with a cBPF JIT and
have not yet migrated to an eBPF JIT.

Currently ``x86_64``, ``arm64``, ``ppc64``, ``s390x``, ``mips64``, ``sparc64`` and
``arm`` architectures come with an in-kernel eBPF JIT compiler.

All BPF handling such as loading of programs into the kernel or creation of BPF maps
is managed through a central ``bpf()`` system call. It is also used for managing map
entries (lookup / update / delete), and making programs as well as maps persistent
in the BPF file system through pinning.

Helper Functions
----------------

Helper functions are a concept which enables BPF programs to consult a core kernel
defined set of function calls in order to retrieve / push data from / to the
kernel. Available helper functions may differ for each BPF program type,
for example, BPF programs attached to sockets are only allowed to call into
a subset of helpers compared to BPF programs attached to the tc layer.
Encapsulation and decapsulation helpers for lightweight tunneling constitute
an example of functions which are only available to lower tc layers, whereas
event output helpers for pushing notifications to user space are available to
tc and XDP programs.

Each helper function is implemented with a commonly shared function signature
similar to system calls. The signature is defined as:

::

    u64 fn(u64 r1, u64 r2, u64 r3, u64 r4, u64 r5)

The calling convention as described in the previous section applies to all
BPF helper functions.

The kernel abstracts helper functions into macros ``BPF_CALL_0()`` to ``BPF_CALL_5()``
which are similar to those of system calls. The following example is an extract
from a helper function which updates map elements by calling into the
corresponding map implementation callbacks:

::

    BPF_CALL_4(bpf_map_update_elem, struct bpf_map *, map, void *, key,
               void *, value, u64, flags)
    {
        WARN_ON_ONCE(!rcu_read_lock_held());
        return map->ops->map_update_elem(map, key, value, flags);
    }

    const struct bpf_func_proto bpf_map_update_elem_proto = {
        .func           = bpf_map_update_elem,
        .gpl_only       = false,
        .ret_type       = RET_INTEGER,
        .arg1_type      = ARG_CONST_MAP_PTR,
        .arg2_type      = ARG_PTR_TO_MAP_KEY,
        .arg3_type      = ARG_PTR_TO_MAP_VALUE,
        .arg4_type      = ARG_ANYTHING,
    };

There are various advantages of this approach: while cBPF overloaded its
load instructions in order to fetch data at an impossible packet offset to
invoke auxiliary helper functions, each cBPF JIT needed to implement support
for such a cBPF extension. In case of eBPF, each newly added helper function
will be JIT compiled in a transparent and efficient way, meaning that the JIT
compiler only needs to emit a call instruction since the register mapping
is made in such a way that BPF register assignments already match the
underlying architecture's calling convention. This allows for easily extending
the core kernel with new helper functionality.

The aforementioned function signature also allows the verifier to perform type
checks. The above ``struct bpf_func_proto`` is used to hand all the necessary
information which need to be known about the helper to the verifier, so that
the verifier can make sure that the expected types from the helper match the
current contents of the BPF program's analyzed registers.

Argument types can range from passing in any kind of value up to restricted
contents such as a pointer / size pair for the BPF stack buffer, which the
helper should read from or write to. In the latter case, the verifier can also
perform additional checks, for example, whether the buffer was previously
initialized.

Maps
----

Maps are efficient key / value stores that reside in kernel space. They can be
accessed from a BPF program in order to keep state among multiple BPF program
invocations. They can also be accessed through file descriptors from user space
and can be arbitrarily shared with other BPF programs or user space applications.

BPF programs which share maps with each other are not required to be of the same
program type, for example, tracing programs can share maps with networking programs.
A single BPF program can currently access up to 64 different maps directly.

Map implementations are provided by the core kernel. There are generic maps with
per-CPU and non-per-CPU flavor that can read / write arbitrary data, but there are
also a few non-generic maps that are used along with helper functions.

Generic maps currently available:

* ``BPF_MAP_TYPE_HASH``
* ``BPF_MAP_TYPE_ARRAY``
* ``BPF_MAP_TYPE_PERCPU_HASH``
* ``BPF_MAP_TYPE_PERCPU_ARRAY``
* ``BPF_MAP_TYPE_LRU_HASH``
* ``BPF_MAP_TYPE_LRU_PERCPU_HASH``
* ``BPF_MAP_TYPE_LPM_TRIE``

Non-generic maps currently in the kernel:

* ``BPF_MAP_TYPE_PROG_ARRAY``
* ``BPF_MAP_TYPE_PERF_EVENT_ARRAY``
* ``BPF_MAP_TYPE_CGROUP_ARRAY``
* ``BPF_MAP_TYPE_STACK_TRACE``
* ``BPF_MAP_TYPE_ARRAY_OF_MAPS``
* ``BPF_MAP_TYPE_HASH_OF_MAPS``

TODO: further coverage of maps and their purpose

Object Pinning
--------------

BPF maps and programs act as a kernel resource and can only be accessed through
file descriptors, backed by anonymous inodes in the kernel. Advantages, but
also a number of disadvantages come along with them:

User space applications can make use of most file descriptor related APIs,
file descriptor passing for Unix domain sockets work transparently, etc, but
at the same time, file descriptors are limited to a processes' lifetime,
which makes options like map sharing rather cumbersome to carry out.

Thus, it brings a number of complications for certain use cases such as iproute2,
where tc or XDP sets up and loads the program into the kernel and terminates
itself eventually. With that, also access to maps is unavailable from user
space side, where it could otherwise be useful, for example, when maps are
shared between ingress and egress locations of the data path. Also, third
party applications may wish to monitor or update map contents during BPF
program runtime.

To overcome this limitation, a minimal kernel space BPF file system has been
implemented, where BPF map and programs can be pinned to, a process called
object pinning. The BPF system call has therefore been extended with two new
commands which can pin (``BPF_OBJ_PIN``) or retrieve (``BPF_OBJ_GET``) a
previously pinned object.

For instance, tools such as tc make use of this infrastructure for sharing
maps on ingress and egress. The BPF related file system is not a singleton,
it does support multiple mount instances, hard and soft links, etc.

Tail Calls
----------

Another concept that can be used with BPF is called tail calls. Tail calls can
be seen as a mechanism that allows one BPF program to call another, without
returning back to the old program. Such a call has minimal overhead as unlike
function calls, it is implemented as a long jump, reusing the same stack frame.

Such programs are verified independently of each other, thus for transferring
state, either per-CPU maps as scratch buffers or in case of tc programs, ``skb``
fields such as the ``cb[]`` area must be used.

Only programs of the same type can be tail called, and they also need to match
in terms of JIT compilation, thus either JIT compiled or only interpreted programs
can be invoked, but not mixed together.

There are two components involved for carrying out tail calls: the first part
needs to setup a specialized map called program array (``BPF_MAP_TYPE_PROG_ARRAY``)
that can be populated by user space with key / values, where values are the
file descriptors of the tail called BPF programs, the second part is a
``bpf_tail_call()`` helper where the context, a reference to the program array
and the lookup key is passed to. Then the kernel inlines this helper call
directly into a specialized BPF instruction. Such a program array is currently
write-only from user space side.

The kernel looks up the related BPF program from the passed file descriptor
and atomically replaces program pointers at the given map slot. When no map
entry has been found at the provided key, the kernel will just "fall through"
and continue execution of the old program with the instructions following
after the ``bpf_tail_call()``. Tail calls are a powerful utility, for example,
parsing network headers could be structured through tail calls. During runtime,
functionality can be added or replaced atomically, and thus altering the BPF
program's execution behaviour.

JIT
---

The 64 bit ``x86_64``, ``arm64``, ``ppc64``, ``s390x``, ``mips64``, ``sparc64``
and 32 bit ``arm`` architectures are all shipped with an in-kernel eBPF JIT
compiler, also all of them are feature equivalent and can be enabled through:

::

    # echo 1 > /proc/sys/net/core/bpf_jit_enable

The 32 bit ``mips``, ``ppc`` and ``sparc`` architectures currently have a cBPF
JIT compiler. The mentioned architectures still having a cBPF JIT as well as all
remaining architectures supported by the Linux kernel which do not have a BPF JIT
compiler at all need to run eBPF programs through the in-kernel interpreter.

In the kernel's source tree, eBPF JIT support can be easily determined through
issuing a grep for ``HAVE_EBPF_JIT``:

::

    # git grep HAVE_EBPF_JIT arch/
    arch/arm/Kconfig:       select HAVE_EBPF_JIT   if !CPU_ENDIAN_BE32
    arch/arm64/Kconfig:     select HAVE_EBPF_JIT
    arch/powerpc/Kconfig:   select HAVE_EBPF_JIT   if PPC64
    arch/mips/Kconfig:      select HAVE_EBPF_JIT   if (64BIT && !CPU_MICROMIPS)
    arch/s390/Kconfig:      select HAVE_EBPF_JIT   if PACK_STACK && HAVE_MARCH_Z196_FEATURES
    arch/sparc/Kconfig:     select HAVE_EBPF_JIT   if SPARC64
    arch/x86/Kconfig:       select HAVE_EBPF_JIT   if X86_64

Hardening
---------

BPF locks the entire BPF interpreter image (``struct bpf_prog``) as well
as the JIT compiled image (``struct bpf_binary_header``) in the kernel as
read-only during the program's lifetime in order to prevent the code from
potential corruptions. Any corruption happening at that point, for example,
due to some kernel bugs will result in a general protection fault and thus
crash the kernel instead of allowing the corruption to happen silently.

Architectures that support setting the image memory as read-only can be
determined through:

::

    $ git grep ARCH_HAS_SET_MEMORY | grep select
    arch/arm/Kconfig:    select ARCH_HAS_SET_MEMORY
    arch/arm64/Kconfig:  select ARCH_HAS_SET_MEMORY
    arch/s390/Kconfig:   select ARCH_HAS_SET_MEMORY
    arch/x86/Kconfig:    select ARCH_HAS_SET_MEMORY

The option ``CONFIG_ARCH_HAS_SET_MEMORY`` is not configurable, thanks to
which this protection is always built-in. Other architectures might follow
in the future.

In case of ``/proc/sys/net/core/bpf_jit_harden`` set to ``1`` additional
hardening steps for the JIT compilation take effect for unprivileged users.
This effectively trades off their performance slightly by decreasing a
(potential) attack surface in case of untrusted users operating on the
system. The decrease in program execution still results in better performance
compared to switching to interpreter entirely.

Currently, enabling hardening will blind all user provided 32 bit and 64 bit
constants from the BPF program when it gets JIT compiled in order to prevent
JIT spraying attacks which inject native opcodes as immediate values. This is
problematic as these immediate values reside in executable kernel memory,
therefore a jump that could be triggered from some kernel bug would jump to
the start of the immediate value and then execute these as native instructions.

JIT constant blinding prevents this due to randomizing the actual instruction,
which means the operation is transformed from an immediate based source operand
to a register based one through rewriting the instruction by splitting the
actual load of the value into two steps: 1) load of a blinded immediate
value ``rnd ^ imm`` into a register, 2) xoring that register with ``rnd``
such that the original ``imm`` immediate then resides in the register and
can be used for the actual operation. The example was provided for a load
operation, but really all generic operations are blinded.

Example of JITing a program with hardening disabled:

::

    # echo 0 > /proc/sys/net/core/bpf_jit_harden

      ffffffffa034f5e9 + <x>:
      [...]
      39:   mov    $0xa8909090,%eax
      3e:   mov    $0xa8909090,%eax
      43:   mov    $0xa8ff3148,%eax
      48:   mov    $0xa89081b4,%eax
      4d:   mov    $0xa8900bb0,%eax
      52:   mov    $0xa810e0c1,%eax
      57:   mov    $0xa8908eb4,%eax
      5c:   mov    $0xa89020b0,%eax
      [...]

The same program gets constant blinded when loaded through BPF
as an unprivileged user in the case hardening is enabled:

::

    # echo 1 > /proc/sys/net/core/bpf_jit_harden

      ffffffffa034f1e5 + <x>:
      [...]
      39:   mov    $0xe1192563,%r10d
      3f:   xor    $0x4989b5f3,%r10d
      46:   mov    %r10d,%eax
      49:   mov    $0xb8296d93,%r10d
      4f:   xor    $0x10b9fd03,%r10d
      56:   mov    %r10d,%eax
      59:   mov    $0x8c381146,%r10d
      5f:   xor    $0x24c7200e,%r10d
      66:   mov    %r10d,%eax
      69:   mov    $0xeb2a830e,%r10d
      6f:   xor    $0x43ba02ba,%r10d
      76:   mov    %r10d,%eax
      79:   mov    $0xd9730af,%r10d
      7f:   xor    $0xa5073b1f,%r10d
      86:   mov    %r10d,%eax
      89:   mov    $0x9a45662b,%r10d
      8f:   xor    $0x325586ea,%r10d
      96:   mov    %r10d,%eax
      [...]

Both programs are semantically the same, only that none of the
original immediate values are visible anymore in the disassembly of
the second program.

At the same time, hardening also disables any JIT kallsyms exposure
for privileged users, preventing that JIT image addresses are not
exposed to ``/proc/kallsyms`` anymore.

Offloads
--------

Networking programs in BPF, in particular for tc and XDP do have an
offload-interface to hardware in the kernel in order to execute BPF
code directly on the NIC.

Currently, the ``nfp`` driver from Netronome has support for offloading
BPF through a JIT compiler which translates BPF instructions to an
instruction set implemented against the NIC.

Toolchain
=========

Current user space tooling, introspection facilities and kernel control knobs around
BPF are discussed in this section. Note, the tooling and infrastructure around BPF
is still rapidly evolving and thus may not provide a complete picture of all available
tools.

Development Environment
-----------------------

A step by step guide for setting up a development environment for BPF can be found
below for both Fedora and Ubuntu. This will guide you through building, installing
and testing a development kernel as well as building and installing iproute2.

The step of building your own iproute2 and Linux kernel is usually not necessary
given that major distributions already ship recent enough kernels by default, but
would be needed for testing bleeding edge versions or contributing BPF patches to
iproute2 and to the Linux kernel, respectively.

Fedora
``````

The following applies to Fedora 25 or later:

::

    $ sudo dnf install -y git gcc ncurses-devel elfutils-libelf-devel bc \
      openssl-devel libcap-devel clang llvm

.. note:: If you are running some other Fedora derivative and ``dnf`` is missing,
          try using ``yum`` instead.

Ubuntu
``````

The following applies to Ubuntu 17.04 or later:

::

    $ sudo apt-get install -y make gcc libssl-dev bc libelf-dev libcap-dev \
      clang gcc-multilib llvm libncurses5-dev git pkg-config libmnl bison flex

Compiling the Kernel
````````````````````

Development of new BPF features for the Linux kernel happens inside the ``net-next``
git tree, latest BPF fixes in the ``net`` tree. The following command will obtain
the kernel source for the ``net-next`` tree through git:

::

    $ git clone git://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git

If the git commit history is not of interest, then ``--depth 1`` will clone the
tree much faster by truncating the git history only to the most recent commit.

In case the ``net`` tree is of interest, it can be cloned from this url:

::

    $ git clone git://git.kernel.org/pub/scm/linux/kernel/git/davem/net.git

There are dozens of tutorials in the Internet on how to build Linux kernels, one
good resource is the Kernel Newbies website (https://kernelnewbies.org/KernelBuild)
that can be followed with one of the two git trees mentioned above.

Make sure that the generated ``.config`` file contains the following ``CONFIG_*``
entries for running BPF. These entries are also needed for Cilium.

::

    CONFIG_CGROUP_BPF=y
    CONFIG_BPF=y
    CONFIG_BPF_SYSCALL=y
    CONFIG_NET_SCH_INGRESS=m
    CONFIG_NET_CLS_BPF=m
    CONFIG_NET_CLS_ACT=y
    CONFIG_BPF_JIT=y
    CONFIG_LWTUNNEL_BPF=y
    CONFIG_HAVE_EBPF_JIT=y
    CONFIG_BPF_EVENTS=y
    CONFIG_TEST_BPF=m

Some of the entries cannot be adjusted through ``make menuconfig``. For example,
``CONFIG_HAVE_EBPF_JIT`` is selected automatically if a given architecture does
come with an eBPF JIT. In this specific case, ``CONFIG_HAVE_EBPF_JIT`` is optional
but highly recommended. An architecture not having an eBPF JIT compiler will need
to fall back to the in-kernel interpreter with the cost of being less efficient
executing BPF instructions.

Verifying the Setup
```````````````````

After you have booted into the newly compiled kernel, navigate to the BPF selftest
suite in order to test BPF functionality (current working directory points to
the root of the cloned git tree):

::

    $ cd tools/testing/selftests/bpf/
    $ make
    $ sudo ./test_verifier

The verifier tests print out all the current checks being performed. The summary
at the end of running all tests will dump information of test successes and
failures:

::

    Summary: 418 PASSED, 0 FAILED

In order to run through all BPF selftests, the following command is needed:

::

    $ sudo make run_tests

If you see any failures, please contact us on Slack with the full test output.

Compiling iproute2
``````````````````

Similar to the ``net`` (fixes only) and ``net-next`` (new features) kernel trees,
the iproute2 git tree has two branches, namely ``master`` and ``net-next``. The
``master`` branch is based on the ``net`` tree and the ``net-next`` branch is
based against the ``net-next`` kernel tree. This is necessary, so that changes
in header files can be synchronized in the iproute2 tree.

In order to clone the iproute2 ``master`` branch, the following command can
be used:

::

    $ git clone git://git.kernel.org/pub/scm/linux/kernel/git/shemminger/iproute2.git

Similarly, to clone into mentioned ``net-next`` branch of iproute2, run the
following:

::

    $ git clone -b net-next git://git.kernel.org/pub/scm/linux/kernel/git/shemminger/iproute2.git

After that, proceed with the build and installation:

::

    $ cd iproute2/
    $ ./configure --prefix=/usr
    TC schedulers
     ATM    no

    libc has setns: yes
    SELinux support: yes
    ELF support: yes
    libmnl support: no
    Berkeley DB: no

    docs: latex: no
     WARNING: no docs can be built from LaTeX files
     sgml2html: no
     WARNING: no HTML docs can be built from SGML
    $ make
    [...]
    $ sudo make install

Ensure that the ``configure`` script shows ``ELF support: yes``, so that iproute2
can process ELF files from LLVM's BPF back end. libelf was listed in the instructions
for installing the dependencies in case of Fedora and Ubuntu earlier.

LLVM
----

LLVM is currently the only compiler suite providing a BPF back end. gcc does
not support BPF at this point.

The BPF back end was merged into LLVM's 3.7 release. Major distributions enable
the BPF back end by default when they package LLVM, therefore installing clang
and llvm is sufficient on most recent distributions to start compiling C
into BPF object files.

The typical workflow is that BPF programs are written in C, compiled by LLVM
into object / ELF files, which are parsed by user space BPF ELF loaders (such as
iproute2 or others), and pushed into the kernel through the BPF system call.
The kernel verifies the BPF instructions and JITs them, returning a new file
descriptor for the program, which then can be attached to a subsystem (e.g.
networking). If supported, the subsystem could then further offload the BPF
program to hardware (e.g. NIC).

For LLVM, BPF target support can be checked, for example, through the following:

::

    $ llc --version
    LLVM (http://llvm.org/):
    LLVM version 3.8.1
    Optimized build.
    Default target: x86_64-unknown-linux-gnu
    Host CPU: skylake

    Registered Targets:
      [...]
      bpf        - BPF (host endian)
      bpfeb      - BPF (big endian)
      bpfel      - BPF (little endian)
      [...]

By default, the ``bpf`` target uses the endianness of the CPU it compiles on,
meaning that if the CPU's endianness is little endian, the program is represented
in little endian format as well, and if the CPU's endianness is big endian,
the program is represented in big endian. This also matches the runtime behavior
of BPF, which is generic and uses the CPU's endianness it runs on in order
to not disadvantage architectures in any of the format.

For cross-compilation, the two targets ``bpfeb`` and ``bpfel`` were introduced,
thanks to that BPF programs can be compiled on a node running in one endianness
(e.g. little endian on x86) and run on a node in another endianness format (e.g.
big endian on arm). Note that the front end (clang) needs to run in the target
endianness as well.

Using ``bpf`` as a target is the preferred way in situations where no mixture of
endianness applies. For example, compilation on ``x86_64`` results in the same
output for the targets ``bpf`` and ``bpfel`` due to being little endian, therefore
scripts triggering a compilation also do not have to be endian aware.

A minimal, stand-alone XDP drop program might look like the following example
(``xdp-example.c``):

::

    #include <linux/bpf.h>

    #ifndef __section
    # define __section(NAME)                  \
       __attribute__((section(NAME), used))
    #endif

    __section("prog")
    int xdp_drop(struct xdp_md *ctx)
    {
        return XDP_DROP;
    }

    char __license[] __section("license") = "GPL";

It can then be compiled and loaded into the kernel as follows:

::

    $ clang -O2 -Wall -target bpf -c xdp-example.c -o xdp-example.o
    # ip link set dev em1 xdp obj xdp-example.o

.. note:: Attaching an XDP BPF program to a network device as above requires
          Linux 4.11 with a device that supports XDP, or Linux 4.12 or later.

For the generated object file LLVM (>= 3.9) uses the official BPF machine value,
that is, ``EM_BPF`` (decimal: ``247`` / hex: ``0xf7``). In this example, the program
has been compiled with ``bpf`` target under ``x86_64``, therefore ``LSB`` (as opposed
to ``MSB``) is shown regarding endianness:

::

    $ file xdp-example.o
    xdp-example.o: ELF 64-bit LSB relocatable, *unknown arch 0xf7* version 1 (SYSV), not stripped

``readelf -a xdp-example.o`` will dump further information about the ELF file, which can
sometimes be useful for introspecting generated section headers, relocation entries
and the symbol table.

In the unlikely case where clang and LLVM need to be compiled from scratch, the
following commands can be used:

::

    $ git clone http://llvm.org/git/llvm.git
    $ cd llvm/tools
    $ git clone --depth 1 http://llvm.org/git/clang.git
    $ cd ..; mkdir build; cd build
    $ cmake .. -DLLVM_TARGETS_TO_BUILD="BPF;X86" -DBUILD_SHARED_LIBS=OFF -DCMAKE_BUILD_TYPE=Release -DLLVM_BUILD_RUNTIME=OFF
    $ make -j $(getconf _NPROCESSORS_ONLN)

    $ ./bin/llc --version
    LLVM (http://llvm.org/):
    LLVM version x.y.zsvn
    Optimized build.
    Default target: x86_64-unknown-linux-gnu
    Host CPU: skylake

    Registered Targets:
      bpf    - BPF (host endian)
      bpfeb  - BPF (big endian)
      bpfel  - BPF (little endian)
      x86    - 32-bit X86: Pentium-Pro and above
      x86-64 - 64-bit X86: EM64T and AMD64

    $ export PATH=$PWD/bin:$PATH   # add to ~/.bashrc

Make sure that ``--version`` mentions ``Optimized build.``, otherwise the
compilation time for programs when having LLVM in debugging mode will
significantly increase (e.g. by 10x or more).

For debugging, clang can generate the assembler output as follows:

::

    $ clang -O2 -S -Wall -target bpf -c xdp-example.c -o xdp-example.S
    $ cat xdp-example.S
        .text
        .section    prog,"ax",@progbits
        .globl      xdp_drop
        .p2align    3
    xdp_drop:                             # @xdp_drop
    # BB#0:
        r0 = 1
        exit

        .section    license,"aw",@progbits
        .globl    __license               # @__license
    __license:
        .asciz    "GPL"

Furthermore, more recent LLVM versions (>= 4.0) can also store debugging
information in dwarf format into the object file. This can be done through
the usual workflow by adding ``-g`` for compilation.

::

    $ clang -O2 -g -Wall -target bpf -c xdp-example.c -o xdp-example.o
    $ llvm-objdump -S -no-show-raw-insn xdp-example.o

    xdp-example.o:        file format ELF64-BPF

    Disassembly of section prog:
    xdp_drop:
    ; {
        0:        r0 = 1
    ; return XDP_DROP;
        1:        exit

The ``llvm-objdump`` tool can then annotate the assembler output with the
original C code used in the compilation. The trivial example in this case
does not contain much C code, however, the line numbers shown as ``0:``
and ``1:`` correspond directly to the kernel's verifier log.

This means that in case BPF programs get rejected by the verifier, ``llvm-objdump``
can help to correlate the instructions back to the original C code, which is
highly useful for analysis.

::

    # ip link set dev em1 xdp obj xdp-example.o verb

    Prog section 'prog' loaded (5)!
     - Type:         6
     - Instructions: 2 (0 over limit)
     - License:      GPL

    Verifier analysis:

    0: (b7) r0 = 1
    1: (95) exit
    processed 2 insns

As it can be seen in the verifier analysis, the ``llvm-objdump`` output dumps
the same BPF assembler code as the kernel.

Leaving out the ``-no-show-raw-insn`` option will also dump the raw
``struct bpf_insn`` as hex in front of the assembly:

::

    $ llvm-objdump -S xdp-example.o

    xdp-example.o:        file format ELF64-BPF

    Disassembly of section prog:
    xdp_drop:
    ; {
       0:       b7 00 00 00 01 00 00 00     r0 = 1
    ; return foo();
       1:       95 00 00 00 00 00 00 00     exit

For LLVM IR debugging, the compilation process for BPF can be split into
two steps, generating a binary LLVM IR intermediate file ``xdp-example.bc``, which
can later on be passed to llc:

::

    $ clang -O2 -Wall -emit-llvm -c xdp-example.c -o xdp-example.bc
    $ llc xdp-example.bc -march=bpf -filetype=obj -o xdp-example.o

The generated LLVM IR can also be dumped in human readable format through:

::

    $ clang -O2 -Wall -emit-llvm -S -c xdp-example.c -o -

Note that LLVM's BPF back end currently does not support generating code
that makes use of BPF's 32 bit subregisters. Inline assembly for BPF is
currently unsupported, too.

Furthermore, compilation from BPF assembly (e.g. ``llvm-mc xdp-example.S -arch bpf -filetype=obj -o xdp-example.o``)
is currently not supported either due to missing BPF assembly parser.

When writing C programs for BPF, there are a couple of pitfalls to be aware
of, compared to usual application development with C. The following items
describe some of the differences for the BPF model:

1. **Everything needs to be inlined, there are no function or shared library
   calls available.**

   Shared libraries, etc cannot be used with BPF. However, common library
   code used in BPF programs can be placed into header files and included in
   the main programs. For example, Cilium makes heavy use of it (see ``bpf/lib/``).
   However, this still allows for including header files, for example, from
   the kernel or other libraries and reuse their static inline functions or
   macros / definitions.

   Eventually LLVM needs to compile the entire code into a flat sequence of
   BPF instructions for a given program section. Best practice is to use an
   annotation like ``__inline`` for every library function as shown below.
   The use of ``always_inline`` is recommended, since the compiler could still
   decide to uninline large functions that are only annotated as ``inline``.

   In case the latter happens, LLVM will generate a relocation entry into
   the ELF file, which BPF ELF loaders such as iproute2 cannot resolve and
   will thus produce an error since only BPF maps are valid relocation entries
   which loaders can process.

   ::

    #include <linux/bpf.h>

    #ifndef __section
    # define __section(NAME)                  \
       __attribute__((section(NAME), used))
    #endif

    #ifndef __inline
    # define __inline                         \
       inline __attribute__((always_inline))
    #endif

    static __inline int foo(void)
    {
        return XDP_DROP;
    }

    __section("prog")
    int xdp_drop(struct xdp_md *ctx)
    {
        return foo();
    }

    char __license[] __section("license") = "GPL";

2. **Multiple programs can reside inside a single C file in different sections.**

   C programs for BPF make heavy use of section annotations. A C file is
   typically structured into 3 or more sections. BPF ELF loaders use these
   names to extract and prepare the relevant information in order to load
   the programs and maps through the bpf system call. For example, iproute2
   uses ``maps`` and ``license`` as default section name to find metadata
   needed for map creation and the license for the BPF program, respectively.
   On program creation time the latter is pushed into the kernel as well,
   and enables some of the helper functions which are exposed as GPL only
   in case the program also holds a GPL compatible license, for example
   ``bpf_ktime_get_ns()``, ``bpf_probe_read()`` and others.

   The remaining section names are specific for BPF program code, for example,
   the below code has been modified to contain two program sections, ``ingress``
   and ``egress``. The toy example code demonstrates that both can share a map
   and common static inline helpers such as the ``account_data()`` function.

   The ``xdp-example.c`` example has been modified to a ``tc-example.c``
   example that can be loaded with tc and attached to a netdevice's ingress
   and egress hook.  It accounts the transferred bytes into a map called
   ``acc_map``, which has two map slots, one for traffic accounted on the
   ingress hook, one on the egress hook.

   ::

    #include <linux/bpf.h>
    #include <linux/pkt_cls.h>
    #include <stdint.h>
    #include <iproute2/bpf_elf.h>

    #ifndef __section
    # define __section(NAME)                  \
       __attribute__((section(NAME), used))
    #endif

    #ifndef __inline
    # define __inline                         \
       inline __attribute__((always_inline))
    #endif

    #ifndef lock_xadd
    # define lock_xadd(ptr, val)              \
       ((void)__sync_fetch_and_add(ptr, val))
    #endif

    #ifndef BPF_FUNC
    # define BPF_FUNC(NAME, ...)              \
       (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
    #endif

    static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);

    struct bpf_elf_map acc_map __section("maps") = {
        .type           = BPF_MAP_TYPE_ARRAY,
        .size_key       = sizeof(uint32_t),
        .size_value     = sizeof(uint32_t),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem       = 2,
    };

    static __inline int account_data(struct __sk_buff *skb, uint32_t dir)
    {
        uint32_t *bytes;

        bytes = map_lookup_elem(&acc_map, &dir);
        if (bytes)
                lock_xadd(bytes, skb->len);

        return TC_ACT_OK;
    }

    __section("ingress")
    int tc_ingress(struct __sk_buff *skb)
    {
        return account_data(skb, 0);
    }

    __section("egress")
    int tc_egress(struct __sk_buff *skb)
    {
        return account_data(skb, 1);
    }

    char __license[] __section("license") = "GPL";

  The example also demonstrates a couple of other things which are useful
  to be aware of when developing programs. The code includes kernel headers,
  standard C headers and an iproute2 specific header containing the
  definition of ``struct bpf_elf_map``. iproute2 has a common BPF ELF loader
  and as such the definition of ``struct bpf_elf_map`` is the very same for
  XDP and tc typed programs.

  A ``struct bpf_elf_map`` entry defines a map in the program and contains
  all relevant information (such as key / value size, etc) needed to generate
  a map which is used from the two BPF programs. The structure must be placed
  into the ``maps`` section, so that the loader can find it. There can be
  multiple map declarations of this type with different variable names, but
  all must be annotated with ``__section("maps")``.

  The ``struct bpf_elf_map`` is specific to iproute2. Different BPF ELF
  loaders can have different formats, for example, the libbpf in the kernel
  source tree, which is mainly used by ``perf``, has a different specification.
  iproute2 guarantees backwards compatibility for ``struct bpf_elf_map``.
  Cilium follows the iproute2 model.

  The example also demonstrates how BPF helper functions are mapped into
  the C code and being used. Here, ``map_lookup_elem()`` is defined by
  mapping this function into the ``BPF_FUNC_map_lookup_elem`` enum value
  which is exposed as a helper in ``uapi/linux/bpf.h``. When the program is later
  loaded into the kernel, the verifier checks whether the passed arguments
  are of the expected type and re-points the helper call into a real
  function call. Moreover, ``map_lookup_elem()`` also demonstrates how
  maps can be passed to BPF helper functions. Here, ``&acc_map`` from the
  ``maps`` section is passed as the first argument to ``map_lookup_elem()``.

  Since the defined array map is global, the accounting needs to use an
  atomic operation, which is defined as ``lock_xadd()``. LLVM maps
  ``__sync_fetch_and_add()`` as a built-in function to the BPF atomic
  add instruction, that is, ``BPF_STX | BPF_XADD | BPF_W`` for word sizes.

  Last but not least, the ``struct bpf_elf_map`` tells that the map is to
  be pinned as ``PIN_GLOBAL_NS``. This means that tc will pin the map
  into the BPF pseudo file system as a node. By default, it will be pinned
  to ``/sys/fs/bpf/tc/globals/acc_map`` for the given example. Due to the
  ``PIN_GLOBAL_NS``, the map will be placed under ``/sys/fs/bpf/tc/globals/``.
  ``globals`` acts as a global namespace that spans across object files.
  If the example used ``PIN_OBJECT_NS``, then tc would create a directory
  that is local to the object file. For example, different C files with
  BPF code could have the same ``acc_map`` definition as above with a
  ``PIN_GLOBAL_NS`` pinning. In that case, the map will be shared among
  BPF programs originating from various object files. ``PIN_NONE`` would
  mean that the map is not placed into the BPF file system as a node,
  and as a result will not be accessible from user space after tc quits. It
  would also mean that tc creates two separate map instances for each
  program, since it cannot retrieve a previously pinned map under that
  name. The ``acc_map`` part from the mentioned path is the name of the
  map as specified in the source code.

  Thus, upon loading of the ``ingress`` program, tc will find that no such
  map exists in the BPF file system and creates a new one. On success, the
  map will also be pinned, so that when the ``egress`` program is loaded
  through tc, it will find that such map already exists in the BPF file
  system and will reuse that for the ``egress`` program. The loader also
  makes sure in case maps exist with the same name that also their properties
  (key / value size, etc) match.

  Just like tc can retrieve the same map, also third party applications
  can use the ``BPF_OBJ_GET`` command from the bpf system call in order
  to create a new file descriptor pointing to the same map instance, which
  can then be used to lookup / update / delete map elements.

  The code can be compiled and loaded via iproute2 as follows:

  ::

    $ clang -O2 -Wall -target bpf -c tc-example.c -o tc-example.o

    # tc qdisc add dev em1 clsact
    # tc filter add dev em1 ingress bpf da obj tc-example.o sec ingress
    # tc filter add dev em1 egress bpf da obj tc-example.o sec egress

    # tc filter show dev em1 ingress
    filter protocol all pref 49152 bpf
    filter protocol all pref 49152 bpf handle 0x1 tc-example.o:[ingress] direct-action tag c5f7825e5dac396f

    # tc filter show dev em1 egress
    filter protocol all pref 49152 bpf
    filter protocol all pref 49152 bpf handle 0x1 tc-example.o:[egress] direct-action tag b2fd5adc0f262714

    # mount | grep bpf
    sysfs on /sys/fs/bpf type sysfs (rw,nosuid,nodev,noexec,relatime,seclabel)
    bpf on /sys/fs/bpf type bpf (rw,relatime,mode=0700)

    # tree /sys/fs/bpf/
    /sys/fs/bpf/
    +-- ip -> /sys/fs/bpf/tc/
    +-- tc
    |   +-- globals
    |       +-- acc_map
    +-- xdp -> /sys/fs/bpf/tc/

    4 directories, 1 file

  As soon as packets pass the ``em1`` device, counters from the BPF map will
  be increased.

3. **There are no global variables allowed.**

  For the reasons already mentioned in point 1, BPF cannot have global variables
  as often used in normal C programs.

  However, there is a work-around in that the program can simply use a BPF map
  of type ``BPF_MAP_TYPE_PERCPU_ARRAY`` with just a single slot of arbitrary
  value size. This works, because during execution, BPF programs are guaranteed
  to never get preempted by the kernel and therefore can use the single map entry
  as a scratch buffer for temporary data, for example, to extend beyond the stack
  limitation. This also functions across tail calls, since it has the same
  guarantees with regards to preemption.

  Otherwise, for holding state across multiple BPF program runs, normal BPF
  maps can be used.

4. **There are no const strings or arrays allowed.**

  Defining ``const`` strings or other arrays in the BPF C program does not work
  for the same reasons as pointed out in sections 1 and 3, which is, that relocation
  entries will be generated in the ELF file which will be rejected by loaders due
  to not being part of the ABI towards loaders (loaders also cannot fix up such
  entries as it would require large rewrites of the already compiled BPF sequence).

  In the future, LLVM might detect these occurrences and early throw an error
  to the user.

  Helper functions such as ``trace_printk()`` can be worked around as follows:

  ::

    static void BPF_FUNC(trace_printk, const char *fmt, int fmt_size, ...);

    #ifndef printk
    # define printk(fmt, ...)                                      \
        ({                                                         \
            char ____fmt[] = fmt;                                  \
            trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
        })
    #endif

  The program can then use the macro naturally like ``printk("skb len:%u\n", skb->len);``.
  The output will then be written to the trace pipe. ``tc exec bpf dbg`` can be
  used to retrieve the messages from there.

  The use of the ``trace_printk()`` helper function has a couple of disadvantages
  and thus is not recommended for production usage. Constant strings like the
  ``"skb len:%u\n"`` need to be loaded into the BPF stack each time the helper
  function is called, but also BPF helper functions are limited to a maximum
  of 5 arguments. This leaves room for only 3 additional variables which can be
  passed for dumping.

  Therefore, despite being helpful for quick debugging, it is recommended (for networking
  programs) to use the ``skb_event_output()`` or the ``xdp_event_output()`` helper,
  respectively. They allow for passing custom structs from the BPF program to
  the perf event ring buffer along with an optional packet sample. For example,
  Cilium's monitor makes use of these helpers in order to implement a debugging
  framework, notifications for network policy violations, etc. These helpers pass
  the data through a lockless memory mapped per-CPU ``perf`` ring buffer, and
  is thus significantly faster than ``trace_printk()``.

5. **Use of LLVM built-in functions for memset()/memcpy()/memmove()/memcmp().**

  Since BPF programs cannot perform any function calls other than those to BPF
  helpers, common library code needs to be implemented as inline functions. In
  addition, also LLVM provides some built-ins that the programs can use for
  constant sizes (here: ``n``) which will then always get inlined:

  ::

    #ifndef memset
    # define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
    #endif

    #ifndef memcpy
    # define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
    #endif

    #ifndef memmove
    # define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
    #endif

  The ``memcmp()`` built-in had some corner cases where inlining did not take place
  due to an LLVM issue in the back end, and is therefore not recommended to be
  used until the issue is fixed.

6. **There are no loops available.**

  The BPF verifier in the kernel checks that a BPF program does not contain
  loops by performing a depth first search of all possible program paths besides
  other control flow graph validations. The purpose is to make sure that the
  program is always guaranteed to terminate.

  A very limited form of looping is available for constant upper loop bounds
  by using ``#pragma unroll`` directive. Example code that is compiled to BPF:

  ::

    #pragma unroll
        for (i = 0; i < IPV6_MAX_HEADERS; i++) {
            switch (nh) {
            case NEXTHDR_NONE:
                return DROP_INVALID_EXTHDR;
            case NEXTHDR_FRAGMENT:
                return DROP_FRAG_NOSUPPORT;
            case NEXTHDR_HOP:
            case NEXTHDR_ROUTING:
            case NEXTHDR_AUTH:
            case NEXTHDR_DEST:
                if (skb_load_bytes(skb, l3_off + len, &opthdr, sizeof(opthdr)) < 0)
                    return DROP_INVALID;

                nh = opthdr.nexthdr;
                if (nh == NEXTHDR_AUTH)
                    len += ipv6_authlen(&opthdr);
                else
                    len += ipv6_optlen(&opthdr);
                break;
            default:
                *nexthdr = nh;
                return len;
            }
        }

  Another possibility is to use tail calls by calling into the same program
  again and using a ``BPF_MAP_TYPE_PERCPU_ARRAY`` map for having a local
  scratch space. While being dynamic, this form of looping however is limited
  to a maximum of 32 iterations.

  In the future, BPF may have some native, but limited form of implementing loops.

7. **Partitioning programs with tail calls.**

  Tail calls provide the flexibility to atomically alter program behavior during
  runtime by jumping from one BPF program into another. In order to select the
  next program, tail calls make use of program array maps (``BPF_MAP_TYPE_PROG_ARRAY``),
  and pass the map as well as the index to the next program to jump to. There is no
  return to the old program after the jump has been performed, and in case there was
  no program present at the given map index, then execution continues on the original
  program.

  For example, this can be used to implement various stages of a parser, where
  such stages could be updated with new parsing features during runtime.

  Another use case are event notifications, for example, Cilium can opt in packet
  drop notifications during runtime, where the ``skb_event_output()`` call is
  located inside the tail called program. Thus, during normal operations, the
  fall-through path will always be executed unless a program is added to the
  related map index, where the program then prepares the metadata and triggers
  the event notification to a user space daemon.

  Program array maps are quite flexible, enabling also individual actions to
  be implemented for programs located in each map index. For example, the root
  program attached to XDP or tc could perform an initial tail call to index 0
  of the program array map, performing traffic sampling, then jumping to index 1
  of the program array map, where firewalling policy is applied and the packet
  either dropped or further processed in index 2 of the program array map, where
  it is mangled and sent out of an interface again. Jumps in the program array
  map can, of course, be arbitrary. The kernel will eventually execute the
  fall-through path when the maximum tail call limit has been reached.

  Minimal example extract of using tail calls:

  ::

    [...]

    #ifndef __stringify
    # define __stringify(X)   #X
    #endif

    #ifndef __section
    # define __section(NAME)                  \
       __attribute__((section(NAME), used))
    #endif

    #ifndef __section_tail
    # define __section_tail(ID, KEY)          \
       __section(__stringify(ID) "/" __stringify(KEY))
    #endif

    #ifndef BPF_FUNC
    # define BPF_FUNC(NAME, ...)              \
       (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
    #endif

    #define BPF_JMP_MAP_ID   1

    static void BPF_FUNC(tail_call, struct __sk_buff *skb, void *map,
                         uint32_t index);

    struct bpf_elf_map jmp_map __section("maps") = {
        .type           = BPF_MAP_TYPE_PROG_ARRAY,
        .id             = BPF_JMP_MAP_ID,
        .size_key       = sizeof(uint32_t),
        .size_value     = sizeof(uint32_t),
        .pinning        = PIN_GLOBAL_NS,
        .max_elem       = 1,
    };

    __section_tail(JMP_MAP_ID, 0)
    int looper(struct __sk_buff *skb)
    {
        printk("skb cb: %u\n", skb->cb[0]++);
        tail_call(skb, &jmp_map, 0);
        return TC_ACT_OK;
    }

    __section("prog")
    int entry(struct __sk_buff *skb)
    {
        skb->cb[0] = 0;
        tail_call(skb, &jmp_map, 0);
        return TC_ACT_OK;
    }

    char __license[] __section("license") = "GPL";

  When loading this toy program, tc will create the program array and pin it
  to the BPF file system in the global namespace under ``jmp_map``. Also, the
  BPF ELF loader in iproute2 will also recognize sections that are marked as
  ``__section_tail()``. The provided ``id`` in ``struct bpf_elf_map`` will be
  matched against the id marker in the ``__section_tail()``, that is, ``JMP_MAP_ID``,
  and the program therefore loaded at the user specified program array map index,
  which is ``0`` in this example. As a result, all provided tail call sections
  will be populated by the iproute2 loader to the corresponding maps. This mechanism
  is not specific to tc, but can be applied with any other BPF program type
  that iproute2 supports (such as XDP, lwt).

  The pinned map can be retrieved by a user space applications (e.g. Cilium daemon),
  but also by tc itself in order to update the map with new programs. Updates
  happen atomically, the initial entry programs that are triggered first from the
  various subsystems are also updated atomically.

  Example for tc to perform tail call map updates:

  ::

    # tc exec bpf graft m:globals/jmp_map key 0 obj new.o sec foo

  In case iproute2 would update the pinned program array, the ``graft`` command
  can be used. By pointing it to ``globals/jmp_map``, tc will update the
  map at index / key ``0`` with a new program residing in the object file ``new.o``
  under section ``foo``.

8. **Limited stack space of 512 bytes.**

  Stack space in BPF programs is limited to only 512 bytes, which needs to be
  taken into careful consideration when implementing BPF programs in C. However,
  as mentioned earlier in point 3, a ``BPF_MAP_TYPE_PERCPU_ARRAY`` map with a
  single entry can be used in order to enlarge scratch buffer space.

iproute2
--------

There are various front ends for loading BPF programs into the kernel such as bcc,
perf, iproute2 and others. The Linux kernel source tree also provides a user space
library under ``tools/lib/bpf/``, which is mainly used and driven by perf for
loading BPF tracing programs into the kernel. However, the library itself is
generic and not limited to perf only. bcc is a toolkit providing many useful
BPF programs mainly for tracing that are loaded ad-hoc through a Python interface
embedding the BPF C code. Syntax and semantics for implementing BPF programs
slightly differ among front ends in general, though. Additionally, there are also
BPF samples in the kernel source tree (``samples/bpf/``) which parse the generated
object files and load the code directly through the system call interface.

This and previous sections mainly focus on the iproute2 suite's BPF front end for
loading networking programs of XDP, tc or lwt type, since Cilium's programs are
implemented against this BPF loader. In future, Cilium will be equipped with a
native BPF loader, but programs will still be compatible to be loaded through
iproute2 suite in order to facilitate development and debugging.

All BPF program types supported by iproute2 share the same BPF loader logic
due to having a common loader back end implemented as a library (``lib/bpf.c``
in iproute2 source tree).

The previous section on LLVM also covered some iproute2 parts related to writing
BPF C programs, and later sections in this document are related to tc and XDP
specific aspects when writing programs. Therefore, this section will rather focus
on usage examples for loading object files with iproute2 as well as some of the
generic mechanics of the loader. It does not try to provide a complete coverage
of all details, but enough for getting started.

**1. Loading of XDP BPF object files.**

  Given a BPF object file ``prog.o`` has been compiled for XDP, it can be loaded
  through ``ip`` to a XDP-supported netdevice called ``em1`` with the following
  command:

  ::

    # ip link set dev em1 xdp obj prog.o

  The above command assumes that the program code resides in the default section
  which is called ``prog`` in XDP case. Should this not be the case, and the
  section is named differently, for example, ``foobar``, then the program needs
  to be loaded as:

  ::

    # ip link set dev em1 xdp obj prog.o sec foobar

  By default, ``ip`` will throw an error in case a XDP program is already attached
  to the networking interface, to prevent it from being overridden by accident. In
  order to replace the currently running XDP program with a new one, the ``-force``
  option must be used:

  ::

    # ip -force link set dev em1 xdp obj prog.o

  Most XDP-enabled drivers today support an atomic replacement of the existing
  program with a new one without traffic interruption. There is always only a
  single program attached to an XDP-enabled driver due to performance reasons,
  hence a chain of programs is not supported. However, as described in the
  previous section, partitioning of programs can be performed through tail
  calls to achieve a similar use case when necessary.

  The ``ip link`` command will display an ``xdp`` flag if the interface has an XDP
  program attached. ``ip link | grep xdp`` can thus be used to find all interfaces
  that have XDP running. Further introspection facilities will be provided through
  the detailed view with ``ip -d link`` once the kernel API gains support for
  dumping additional attributes.

  In order to remove the existing XDP program from the interface, the following
  command must be issued:

  ::

    # ip link set dev em1 xdp off

**2. Loading of tc BPF object files.**

  Given a BPF object file ``prog.o`` has been compiled for tc, it can be loaded
  through the tc command to a netdevice. Unlike XDP, there is no driver dependency
  for supporting attaching BPF programs to the device. Here, the netdevice is called
  ``em1``, and with the following command the program can be attached to the networking
  ``ingress`` path of ``em1``:

  ::

    # tc qdisc add dev em1 clsact
    # tc filter add dev em1 ingress bpf da obj prog.o

  The first step is to set up a ``clsact`` qdisc (Linux queueing discipline). ``clsact``
  is a dummy qdisc similar to the ``ingress`` qdisc, which can only hold classifier
  and actions, but does not perform actual queueing. It is needed in order to attach
  the ``bpf`` classifier. The ``clsact`` qdisc provides two special hooks called
  ``ingress`` and ``egress``, where the classifier can be attached to. Both ``ingress``
  and ``egress`` hooks are located in central receive and transmit locations in the
  networking data path, where every packet on the device passes through. The ``ingress``
  hook is called from ``__netif_receive_skb_core() -> sch_handle_ingress()`` in the
  kernel and the ``egress`` hook from ``__dev_queue_xmit() -> sch_handle_egress()``.

  The equivalent for attaching the program to the ``egress`` hook looks as follows:

  ::

    # tc filter add dev em1 egress bpf da obj prog.o

  The ``clsact`` qdisc is processed lockless from ``ingress`` and ``egress``
  direction and can also be attached to virtual, queue-less devices such as
  ``veth`` devices connecting containers.

  Next to the hook, the ``tc filter`` command selects ``bpf`` to be used in ``da``
  (direct-action) mode. ``da`` mode is recommended and should always be specified.
  It basically means that the ``bpf`` classifier does not need to call into external
  tc action modules, which are not necessary for ``bpf`` anyway, since all packet
  mangling, forwarding or other kind of actions can already be performed inside
  the single BPF program which is to be attached, and is therefore significantly
  faster.

  At this point, the program has been attached and is executed once packets traverse
  the device. Like in XDP, should the default section name not be used, then it
  can be specified during load, for example, in case of section ``foobar``:

  ::

    # tc filter add dev em1 egress bpf da obj prog.o sec foobar

  iproute2's BPF loader allows for using the same command line syntax across
  program types, hence the ``obj prog.o sec foobar`` is the same syntax as with
  XDP mentioned earlier.

  The attached programs can be listed through the following commands:

  ::

    # tc filter show dev em1 ingress
    filter protocol all pref 49152 bpf
    filter protocol all pref 49152 bpf handle 0x1 prog.o:[ingress] direct-action tag c5f7825e5dac396f

    # tc filter show dev em1 egress
    filter protocol all pref 49152 bpf
    filter protocol all pref 49152 bpf handle 0x1 prog.o:[egress] direct-action tag b2fd5adc0f262714

  The output of ``prog.o:[ingress]`` tells that program section ``ingress`` was
  loaded from the file ``prog.o``, and ``bpf`` operates in ``direct-action`` mode.
  The program tags are appended for each, which denotes a hash over the instruction
  stream which can be used for debugging / introspection.

  tc can attach more than just a single BPF program, it provides various other
  classifiers which can be chained together. However, attaching a single BPF program
  is fully sufficient since all packet operations can be contained in the program
  itself thanks to ``da`` (``direct-action``) mode. For optimal performance and
  flexibility, this is the recommended usage.

  In the above ``show`` command, tc also displays ``pref 49152`` and
  ``handle 0x1`` next to the BPF related output. Both are auto-generated in
  case they are not explicitly provided through the command line. ``pref``
  denotes a priority number, which means that in case multiple classifiers are
  attached, they will be executed based on ascending priority, and ``handle``
  represents an identifier in case multiple instances of the same classifier have
  been loaded under the same ``pref``. Since in case of BPF, a single program is
  fully sufficient, ``pref`` and ``handle`` can typically be ignored.

  Only in the case where it is planned to atomically replace the attached BPF
  programs, it would be recommended to explicitly specify ``pref`` and ``handle``
  a priori on initial load, so that they do not have to be queried at a later
  point in time for the ``replace`` operation. Thus, creation becomes:

  ::

    # tc filter add dev em1 ingress pref 1 handle 1 bpf da obj prog.o sec foobar

    # tc filter show dev em1 ingress
    filter protocol all pref 1 bpf
    filter protocol all pref 1 bpf handle 0x1 prog.o:[foobar] direct-action tag c5f7825e5dac396f

  And for the atomic replacement, the following can be issued for updating the
  existing program at ``ingress`` hook with the new BPF program from the file
  ``prog.o`` in section ``foobar``:

  ::

    # tc filter replace dev em1 ingress pref 1 handle 1 bpf da obj prog.o sec foobar

  Last but not least, in order to remove all attached programs from the ``ingress``
  respectively ``egress`` hook, the following can be used:

  ::

    # tc filter del dev em1 ingress
    # tc filter del dev em1 egress

  For removing the entire ``clsact`` qdisc from the netdevice, which implicitly also
  removes all attached programs from the ``ingress`` and ``egress`` hooks, the
  below command is provided:

  ::

    # tc qdisc del dev em1 clsact

These two workflows are the basic operations to load XDP BPF respectively tc BPF
programs with iproute2.

There are other various advanced options for the BPF loader that apply both to XDP
and tc, some of them are listed here. In the examples only XDP is presented for
simplicity.

**1. Verbose log output even on success.**

  The option ``verb`` can be appended for loading programs in order to dump the
  verifier log, even if no error occurred:

  ::

    # ip link set dev em1 xdp obj xdp-example.o verb

    Prog section 'prog' loaded (5)!
     - Type:         6
     - Instructions: 2 (0 over limit)
     - License:      GPL

    Verifier analysis:

    0: (b7) r0 = 1
    1: (95) exit
    processed 2 insns

**2. Load program that is already pinned in BPF file system.**

  Instead of loading a program from an object file, iproute2 can also retrieve
  the program from the BPF file system in case some external entity pinned it
  there and attach it to the device:

  ::

  # ip link set dev em1 xdp pinned /sys/fs/bpf/prog

  iproute2 can also use the short form that is relative to the detected mount
  point of the BPF file system:

  ::

  # ip link set dev em1 xdp pinned m:prog

When loading BPF programs, iproute2 will automatically detect the mounted
file system instance in order to perform pinning of nodes. In case no mounted
BPF file system instance was found, then tc will automatically mount it
to the default location under ``/sys/fs/bpf/``.

In case an instance has already been found, then it will be used and no additional
mount will be performed:

  ::

    # mkdir /var/run/bpf
    # mount --bind /var/run/bpf /var/run/bpf
    # mount -t bpf bpf /var/run/bpf
    # tc filter add dev em1 ingress bpf da obj tc-example.o sec prog
    # tree /var/run/bpf
    /var/run/bpf
    +-- ip -> /run/bpf/tc/
    +-- tc
    |   +-- globals
    |       +-- jmp_map
    +-- xdp -> /run/bpf/tc/

    4 directories, 1 file

By default tc will create an initial directory structure as shown above,
where all subsystem users will point to the same location through symbolic
links for the ``globals`` namespace, so that pinned BPF maps can be reused
among various BPF program types in iproute2. In case the file system instance
has already been mounted and an existing structure already exists, then tc will
not override it. This could be the case for separating ``lwt``, ``tc`` and
``xdp`` maps in order to not share ``globals`` among all.

As briefly covered in the previous LLVM section, iproute2 will install a
header file upon installation which can be included through the standard
include path by BPF programs:

  ::

    #include <iproute2/bpf_elf.h>

The purpose of this header file is to provide an API for maps and default section
names used by programs. It's a stable contract between iproute2 and BPF programs.

The map definition for iproute2 is ``struct bpf_elf_map``. Its members have
been covered earlier in the LLVM section of this document.

When parsing the BPF object file, the iproute2 loader will walk through
all ELF sections. It initially fetches ancillary sections like ``maps`` and
``license``. For ``maps``, the ``struct bpf_elf_map`` array will be checked
for validity and whenever needed, compatibility workarounds are performed.
Subsequently all maps are created with the user provided information, either
retrieved as a pinned object, or newly created and then pinned into the BPF
file system. Next the loader will handle all program sections that contain
ELF relocation entries for maps, meaning that BPF instructions loading
map file descriptors into registers are rewritten so that the corresponding
map file descriptors are encoded into the instructions immediate value, in
order for the kernel to be able to convert them later on into map kernel
pointers. After that all the programs themselves are created through the BPF
system call, and tail called maps, if present, updated with the program's file
descriptors.

BPF sysctls
-----------

The Linux kernel provides few sysctls that are BPF related and covered in this section.

* ``/proc/sys/net/core/bpf_jit_enable``: Enables or disables the BPF JIT compiler.

  +-------+-------------------------------------------------------------------+
  | Value | Description                                                       |
  +-------+-------------------------------------------------------------------+
  | 0     | Disable the JIT and use only interpreter (kernel's default value) |
  +-------+-------------------------------------------------------------------+
  | 1     | Enable the JIT compiler                                           |
  +-------+-------------------------------------------------------------------+
  | 2     | Enable the JIT and emit debugging traces to the kernel log        |
  +-------+-------------------------------------------------------------------+

  As described in subsequent sections, ``bpf_jit_disasm`` tool can be used to
  process debugging traces when the JIT compiler is set to debugging mode (option ``2``).

* ``/proc/sys/net/core/bpf_jit_harden``: Enables or disables BPF JIT hardening.
  Note that enabling hardening trades off performance, but can mitigate JIT spraying
  by blinding out the BPF program's immediate values. For programs processed through
  the interpreter, blinding of immediate values is not needed / performed.

  +-------+-------------------------------------------------------------------+
  | Value | Description                                                       |
  +-------+-------------------------------------------------------------------+
  | 0     | Disable JIT hardening (kernel's default value)                    |
  +-------+-------------------------------------------------------------------+
  | 1     | Enable JIT hardening for unprivileged users only                  |
  +-------+-------------------------------------------------------------------+
  | 2     | Enable JIT hardening for all users                                |
  +-------+-------------------------------------------------------------------+

* ``/proc/sys/net/core/bpf_jit_kallsyms``: Enables or disables export of JITed
  programs as kernel symbols to ``/proc/kallsyms`` so that they can be used together
  with ``perf`` tooling as well as making these addresses aware to the kernel for
  stack unwinding, for example, used in dumping stack traces. The symbol names
  contain the BPF program tag (``bpf_prog_<tag>``). If ``bpf_jit_harden`` is enabled,
  then this feature is disabled.

  +-------+-------------------------------------------------------------------+
  | Value | Description                                                       |
  +-------+-------------------------------------------------------------------+
  | 0     | Disable JIT kallsyms export (kernel's default value)              |
  +-------+-------------------------------------------------------------------+
  | 1     | Enable JIT kallsyms export for privileged users only              |
  +-------+-------------------------------------------------------------------+

Kernel Testing
--------------

The Linux kernel ships a BPF selftest suite, which can be found in the kernel
source tree under ``tools/testing/selftests/bpf/``.

::

    $ cd tools/testing/selftests/bpf/
    $ make
    # make run_tests

The test suite contains test cases against the BPF verifier, program tags,
various tests against the BPF map interface and map types. It contains various
runtime tests from C code for checking LLVM back end, and eBPF as well as cBPF
asm code that is run in the kernel for testing the interpreter and JITs.

JIT Debugging
-------------

For JIT developers performing audits or writing extensions, each compile run
can output the generated JIT image into the kernel log through:

::

    # echo 2 > /proc/sys/net/core/bpf_jit_enable

Whenever a new BPF program is loaded, the JIT compiler will dump the output,
which can then be inspected with ``dmesg``, for example:

::

    [ 3389.935842] flen=6 proglen=70 pass=3 image=ffffffffa0069c8f from=tcpdump pid=20583
    [ 3389.935847] JIT code: 00000000: 55 48 89 e5 48 83 ec 60 48 89 5d f8 44 8b 4f 68
    [ 3389.935849] JIT code: 00000010: 44 2b 4f 6c 4c 8b 87 d8 00 00 00 be 0c 00 00 00
    [ 3389.935850] JIT code: 00000020: e8 1d 94 ff e0 3d 00 08 00 00 75 16 be 17 00 00
    [ 3389.935851] JIT code: 00000030: 00 e8 28 94 ff e0 83 f8 01 75 07 b8 ff ff 00 00
    [ 3389.935852] JIT code: 00000040: eb 02 31 c0 c9 c3

``flen`` is the length of the BPF program (here, 6 BPF instructions), and ``proglen``
tells the number of bytes generated by the JIT for the opcode image (here, 70 bytes
in size). ``pass`` means that the image was generated in 3 compiler passes, for
example, ``x86_64`` can have various optimization passes to further reduce the image
size when possible. ``image`` contains the address of the generated JIT image, ``from``
and ``pid`` the user space application name and PID respectively, which triggered the
compilation process. The dump output for eBPF and cBPF JITs is the same format.

In the kernel tree under ``tools/net/``, there is a tool called ``bpf_jit_disasm``. It
reads out the latest dump and prints the disassembly for further inspection:

::

    # ./bpf_jit_disasm
    70 bytes emitted from JIT compiler (pass:3, flen:6)
    ffffffffa0069c8f + <x>:
       0:       push   %rbp
       1:       mov    %rsp,%rbp
       4:       sub    $0x60,%rsp
       8:       mov    %rbx,-0x8(%rbp)
       c:       mov    0x68(%rdi),%r9d
      10:       sub    0x6c(%rdi),%r9d
      14:       mov    0xd8(%rdi),%r8
      1b:       mov    $0xc,%esi
      20:       callq  0xffffffffe0ff9442
      25:       cmp    $0x800,%eax
      2a:       jne    0x0000000000000042
      2c:       mov    $0x17,%esi
      31:       callq  0xffffffffe0ff945e
      36:       cmp    $0x1,%eax
      39:       jne    0x0000000000000042
      3b:       mov    $0xffff,%eax
      40:       jmp    0x0000000000000044
      42:       xor    %eax,%eax
      44:       leaveq
      45:       retq

Alternatively, the tool can also dump related opcodes along with the disassembly.

::

    # ./bpf_jit_disasm -o
    70 bytes emitted from JIT compiler (pass:3, flen:6)
    ffffffffa0069c8f + <x>:
       0:       push   %rbp
        55
       1:       mov    %rsp,%rbp
        48 89 e5
       4:       sub    $0x60,%rsp
        48 83 ec 60
       8:       mov    %rbx,-0x8(%rbp)
        48 89 5d f8
       c:       mov    0x68(%rdi),%r9d
        44 8b 4f 68
      10:       sub    0x6c(%rdi),%r9d
        44 2b 4f 6c
      14:       mov    0xd8(%rdi),%r8
        4c 8b 87 d8 00 00 00
      1b:       mov    $0xc,%esi
        be 0c 00 00 00
      20:       callq  0xffffffffe0ff9442
        e8 1d 94 ff e0
      25:       cmp    $0x800,%eax
        3d 00 08 00 00
      2a:       jne    0x0000000000000042
        75 16
      2c:       mov    $0x17,%esi
        be 17 00 00 00
      31:       callq  0xffffffffe0ff945e
        e8 28 94 ff e0
      36:       cmp    $0x1,%eax
        83 f8 01
      39:       jne    0x0000000000000042
        75 07
      3b:       mov    $0xffff,%eax
        b8 ff ff 00 00
      40:       jmp    0x0000000000000044
        eb 02
      42:       xor    %eax,%eax
        31 c0
      44:       leaveq
        c9
      45:       retq
        c3

For performance analysis of JITed BPF programs, ``perf`` can be used as
usual. As a prerequisite, JITed programs need to be exported through kallsyms
infrastructure.

::

    # echo 1 > /proc/sys/net/core/bpf_jit_enable
    # echo 1 > /proc/sys/net/core/bpf_jit_kallsyms

Enabling or disabling ``bpf_jit_kallsyms`` does not require a reload of the
related BPF programs. Next, a small workflow example is provided for profiling
BPF programs. A crafted tc BPF program is used for demonstration purposes,
where perf records a failed allocation inside ``bpf_clone_redirect()`` helper.
Due to the use of direct write, ``bpf_try_make_head_writable()`` failed, which
would then release the cloned ``skb`` again and return with an error message.
``perf`` thus records all ``kfree_skb`` events.

::

    # tc qdisc add dev em1 clsact
    # tc filter add dev em1 ingress bpf da obj prog.o sec main
    # tc filter show dev em1 ingress
    filter protocol all pref 49152 bpf
    filter protocol all pref 49152 bpf handle 0x1 prog.o:[main] direct-action tag 8227addf251b7543

    # cat /proc/kallsyms
    [...]
    ffffffffc00349e0 t fjes_hw_init_command_registers    [fjes]
    ffffffffc003e2e0 d __tracepoint_fjes_hw_stop_debug_err    [fjes]
    ffffffffc0036190 t fjes_hw_epbuf_tx_pkt_send    [fjes]
    ffffffffc004b000 t bpf_prog_8227addf251b7543

    # perf record -a -g -e skb:kfree_skb sleep 60
    # perf script --kallsyms=/proc/kallsyms
    [...]
    ksoftirqd/0     6 [000]  1004.578402:    skb:kfree_skb: skbaddr=0xffff9d4161f20a00 protocol=2048 location=0xffffffffc004b52c
       7fffb8745961 bpf_clone_redirect (/lib/modules/4.10.0+/build/vmlinux)
       7fffc004e52c bpf_prog_8227addf251b7543 (/lib/modules/4.10.0+/build/vmlinux)
       7fffc05b6283 cls_bpf_classify (/lib/modules/4.10.0+/build/vmlinux)
       7fffb875957a tc_classify (/lib/modules/4.10.0+/build/vmlinux)
       7fffb8729840 __netif_receive_skb_core (/lib/modules/4.10.0+/build/vmlinux)
       7fffb8729e38 __netif_receive_skb (/lib/modules/4.10.0+/build/vmlinux)
       7fffb872ae05 process_backlog (/lib/modules/4.10.0+/build/vmlinux)
       7fffb872a43e net_rx_action (/lib/modules/4.10.0+/build/vmlinux)
       7fffb886176c __do_softirq (/lib/modules/4.10.0+/build/vmlinux)
       7fffb80ac5b9 run_ksoftirqd (/lib/modules/4.10.0+/build/vmlinux)
       7fffb80ca7fa smpboot_thread_fn (/lib/modules/4.10.0+/build/vmlinux)
       7fffb80c6831 kthread (/lib/modules/4.10.0+/build/vmlinux)
       7fffb885e09c ret_from_fork (/lib/modules/4.10.0+/build/vmlinux)

The stack trace recorded by ``perf`` will then show the ``bpf_prog_8227addf251b7543()``
symbol as part of the call trace, meaning that the BPF program with the
tag ``8227addf251b7543`` was related to the ``kfree_skb`` event, and
such program was attached to netdevice ``em1`` on the ingress hook as
shown by tc.

Introspection
-------------

The Linux kernel provides various tracepoints around BPF and XDP which
can be used for additional introspection, for example, to trace interactions
of user space programs with the bpf system call.

Tracepoints for BPF:

::

    # perf list | grep bpf:
    bpf:bpf_map_create                                 [Tracepoint event]
    bpf:bpf_map_delete_elem                            [Tracepoint event]
    bpf:bpf_map_lookup_elem                            [Tracepoint event]
    bpf:bpf_map_next_key                               [Tracepoint event]
    bpf:bpf_map_update_elem                            [Tracepoint event]
    bpf:bpf_obj_get_map                                [Tracepoint event]
    bpf:bpf_obj_get_prog                               [Tracepoint event]
    bpf:bpf_obj_pin_map                                [Tracepoint event]
    bpf:bpf_obj_pin_prog                               [Tracepoint event]
    bpf:bpf_prog_get_type                              [Tracepoint event]
    bpf:bpf_prog_load                                  [Tracepoint event]
    bpf:bpf_prog_put_rcu                               [Tracepoint event]

Example usage with ``perf`` (alternatively to ``sleep`` example used here,
a specific application like ``tc`` could be used here instead, of course):

::

    # perf record -a -e bpf:* sleep 10
    # perf script
    sock_example  6197 [005]   283.980322:      bpf:bpf_map_create: map type=ARRAY ufd=4 key=4 val=8 max=256 flags=0
    sock_example  6197 [005]   283.980721:       bpf:bpf_prog_load: prog=a5ea8fa30ea6849c type=SOCKET_FILTER ufd=5
    sock_example  6197 [005]   283.988423:   bpf:bpf_prog_get_type: prog=a5ea8fa30ea6849c type=SOCKET_FILTER
    sock_example  6197 [005]   283.988443: bpf:bpf_map_lookup_elem: map type=ARRAY ufd=4 key=[06 00 00 00] val=[00 00 00 00 00 00 00 00]
    [...]
    sock_example  6197 [005]   288.990868: bpf:bpf_map_lookup_elem: map type=ARRAY ufd=4 key=[01 00 00 00] val=[14 00 00 00 00 00 00 00]
         swapper     0 [005]   289.338243:    bpf:bpf_prog_put_rcu: prog=a5ea8fa30ea6849c type=SOCKET_FILTER

For the BPF programs, their individual program tag is displayed.

For debugging, XDP also has a tracepoint that is triggered when exceptions are raised:

::

    # perf list | grep xdp:
    xdp:xdp_exception                                  [Tracepoint event]

Exceptions are triggered in the following scenarios:

* The BPF program returned an invalid / unknown XDP action code.
* The BPF program returned with ``XDP_ABORTED`` indicating a non-graceful exit.
* The BPF program returned with ``XDP_TX``, but there was an error on transmit,
  for example, due to the port not being up, due to the transmit ring being full,
  due to allocation failures, etc.

Both tracepoint classes can also be inspected with a BPF program itself
attached to one or more tracepoints, collecting further information
in a map or punting such events to a user space collector through the
``bpf_perf_event_output()`` helper, for example.

Miscellaneous
-------------

BPF programs and maps are memory accounted against ``RLIMIT_MEMLOCK`` similar
to ``perf``. The currently available size in unit of system pages which may be
locked into memory can be inspected through ``ulimit -l``. The setrlimit system
call man page provides further details.

The default limit is usually insufficient to load more complex programs or
larger BPF maps, so that the BPF system call will return with ``errno``
of ``EPERM``. In such situations a workaround with ``ulimit -l unlimited`` or
with a sufficiently large limit could be performed. The ``RLIMIT_MEMLOCK`` is
mainly enforcing limits for unprivileged users. Depending on the setup,
setting a higher limit for privileged users is often acceptable.

tc (traffic control)
====================

TODO

XDP
===

TODO

.. _bpf_users:

Further Reading
===============

Mentioned lists of projects, talks, papers, and further reading material
are likely not complete. Thus, feel free to open pull requests to complete
the list.

Projects using BPF
------------------

The following list includes some open source projects making use of BPF:

- BCC - tools for BPF-based Linux IO analysis, networking, monitoring, and more
  (https://github.com/iovisor/bcc)
- Cilium
  (https://github.com/cilium/cilium)
- iproute2 (ip and tc tools)
  (https://wiki.linuxfoundation.org/networking/iproute2)
- perf tool
  (https://perf.wiki.kernel.org/index.php/Main_Page)
- ply - a dynamic tracer for Linux
  (https://wkz.github.io/ply)
- Go bindings for creating BPF programs
  (https://github.com/iovisor/gobpf)
- Suricata IDS
  (https://suricata-ids.org)

XDP Newbies
-----------

There are a couple of walk-through posts by David S. Miller to the xdp-newbies
mailing list (http://vger.kernel.org/vger-lists.html#xdp-newbies), which explain
various parts of XDP and BPF:

4. May 2017,
     BPF Verifier Overview,
     David S. Miller,
     https://www.spinics.net/lists/xdp-newbies/msg00185.html

3. May 2017,
     Contextually speaking...,
     David S. Miller,
     https://www.spinics.net/lists/xdp-newbies/msg00181.html

2. May 2017,
     bpf.h and you...,
     David S. Miller,
     https://www.spinics.net/lists/xdp-newbies/msg00179.html

1. Apr 2017,
     XDP example of the day,
     David S. Miller,
     https://www.spinics.net/lists/xdp-newbies/msg00009.html

BPF Newsletter
--------------

Alexander Alemayhu initiated a newsletter around BPF that appears roughly once
per week covering latest developments around BPF in Linux kernel land and its
surrounding ecosystem in user space:

5. May 2017,
     BPF Updates 05,
     Alexander Alemayhu,
     https://www.cilium.io/blog/2017/5/31/bpf-updates-05

4. May 2017,
     BPF Updates 04,
     Alexander Alemayhu,
     https://www.cilium.io/blog/2017/5/24/bpf-updates-04

3. May 2017,
     BPF Updates 03,
     Alexander Alemayhu,
     https://www.cilium.io/blog/2017/5/17/bpf-updates-03

2. May 2017,
     BPF Updates 02,
     Alexander Alemayhu,
     https://www.cilium.io/blog/2017/5/10/bpf-updates-02

1. May 2017,
     BPF Updates 01,
     Alexander Alemayhu,
     https://www.cilium.io/blog/2017/5/2/bpf-updates-01-2017-05-02

Podcasts
--------

There have been a number of technical podcasts partially covering BPF.
Incomplete list:

5. Feb 2017,
     Linux Networking Update from Netdev Conference,
     Thomas Graf,
     Software Gone Wild, Show 71,
     http://blog.ipspace.net/2017/02/linux-networking-update-from-netdev.html
     http://media.blubrry.com/ipspace/stream.ipspace.net/nuggets/podcast/Show_71-NetDev_Update.mp3

4. Jan 2017,
     The IO Visor Project,
     Brenden Blanco,
     OVS Orbit, Episode 23,
     https://ovsorbit.org/#e23
     https://ovsorbit.org/episode-23.mp3

3. Oct 2016,
     Fast Linux Packet Forwarding,
     Thomas Graf,
     Software Gone Wild, Show 64,
     http://blog.ipspace.net/2016/10/fast-linux-packet-forwarding-with.html
     http://media.blubrry.com/ipspace/stream.ipspace.net/nuggets/podcast/Show_64-Cilium_with_Thomas_Graf.mp3

2. Aug 2016,
     P4 on the Edge,
     John Fastabend,
     OVS Orbit, Episode 11,
     https://ovsorbit.org/#e11
     https://ovsorbit.org/episode-11.mp3

1. May 2016,
     Cilium,
     Thomas Graf,
     OVS Orbit, Episode 4,
     https://ovsorbit.org/#e4
     https://ovsorbit.benpfaff.org/episode-4.mp3

Blog posts
----------

The following (incomplete) list includes blog posts around BPF, XDP and related projects:

34. May 2017,
     An entertaining eBPF XDP adventure,
     Suchakra Sharma,
     https://suchakra.wordpress.com/2017/05/23/an-entertaining-ebpf-xdp-adventure/

33. May 2017,
     eBPF, part 2: Syscall and Map Types,
     Ferris Ellis,
     https://ferrisellis.com/posts/ebpf_syscall_and_maps/

32. May 2017,
     Monitoring the Control Plane,
     Gary Berger,
     http://firstclassfunc.com/2017/05/monitoring-the-control-plane/

31. Apr 2017,
     USENIX/LISA 2016 Linux bcc/BPF Tools,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2017-04-29/usenix-lisa-2016-bcc-bpf-tools.html

30. Apr 2017,
     Liveblog: Cilium for Network and Application Security with BPF and XDP,
     Scott Lowe,
     http://blog.scottlowe.org//2017/04/18/black-belt-cilium/

29. Apr 2017,
     eBPF, part 1: Past, Present, and Future,
     Ferris Ellis,
     https://ferrisellis.com/posts/ebpf_past_present_future/

28. Mar 2017,
     Analyzing KVM Hypercalls with eBPF Tracing,
     Suchakra Sharma,
     https://suchakra.wordpress.com/2017/03/31/analyzing-kvm-hypercalls-with-ebpf-tracing/

27. Jan 2017,
     Golang bcc/BPF Function Tracing,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2017-01-31/golang-bcc-bpf-function-tracing.html

26. Dec 2016,
     Give me 15 minutes and I'll change your view of Linux tracing,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-12-27/linux-tracing-in-15-minutes.html

25. Nov 2016,
     Cilium: Networking and security for containers with BPF and XDP,
     Daniel Borkmann,
     https://opensource.googleblog.com/2016/11/cilium-networking-and-security.html

24. Nov 2016,
     Linux bcc/BPF tcplife: TCP Lifespans,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-11-30/linux-bcc-tcplife.html

23. Oct 2016,
     DTrace for Linux 2016,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-27/dtrace-for-linux-2016.html

22. Oct 2016,
     Linux 4.9's Efficient BPF-based Profiler,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-21/linux-efficient-profiler.html

21. Oct 2016,
     Linux bcc tcptop,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-15/linux-bcc-tcptop.html

20. Oct 2016,
     Linux bcc/BPF Node.js USDT Tracing,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-12/linux-bcc-nodejs-usdt.html

19. Oct 2016,
     Linux bcc/BPF Run Queue (Scheduler) Latency,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-08/linux-bcc-runqlat.html

18. Oct 2016,
     Linux bcc ext4 Latency Tracing,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-06/linux-bcc-ext4dist-ext4slower.html

17. Oct 2016,
     Linux MySQL Slow Query Tracing with bcc/BPF,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-04/linux-bcc-mysqld-qslower.html

16. Oct 2016,
     Linux bcc Tracing Security Capabilities,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-10-01/linux-bcc-security-capabilities.html

15. Sep 2016,
     Suricata bypass feature,
     Eric Leblond,
     https://www.stamus-networks.com/2016/09/28/suricata-bypass-feature/

14. Aug 2016,
     Introducing the p0f BPF compiler,
     Gilberto Bertin,
     https://blog.cloudflare.com/introducing-the-p0f-bpf-compiler/

13. Jun 2016,
     Ubuntu Xenial bcc/BPF,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-06-14/ubuntu-xenial-bcc-bpf.html

12. Mar 2016,
     Linux BPF/bcc Road Ahead, March 2016,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-03-28/linux-bpf-bcc-road-ahead-2016.html

11. Mar 2016,
     Linux BPF Superpowers,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-03-05/linux-bpf-superpowers.html

10. Feb 2016,
     Linux eBPF/bcc uprobes,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-02-08/linux-ebpf-bcc-uprobes.html

9. Feb 2016,
     Who is waking the waker? (Linux chain graph prototype),
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-02-05/ebpf-chaingraph-prototype.html

8. Feb 2016,
     Linux Wakeup and Off-Wake Profiling,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-02-01/linux-wakeup-offwake-profiling.html

7. Jan 2016,
     Linux eBPF Off-CPU Flame Graph,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-01-20/ebpf-offcpu-flame-graph.html

6. Jan 2016,
     Linux eBPF Stack Trace Hack,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2016-01-18/ebpf-stack-trace-hack.html

1. Sep 2015,
     Linux Networking, Tracing and IO Visor, a New Systems Performance Tool for a Distributed World,
     Suchakra Sharma,
     https://thenewstack.io/comparing-dtrace-iovisor-new-systems-performance-platform-advance-linux-networking-virtualization/

5. Aug 2015,
     BPF Internals - II,
     Suchakra Sharma,
     https://suchakra.wordpress.com/2015/08/12/bpf-internals-ii/

4. May 2015,
     eBPF: One Small Step,
     Brendan Gregg,
     http://www.brendangregg.com/blog/2015-05-15/ebpf-one-small-step.html

3. May 2015,
     BPF Internals - I,
     Suchakra Sharma,
     https://suchakra.wordpress.com/2015/05/18/bpf-internals-i/

2. Jul 2014,
     Introducing the BPF Tools,
     Marek Majkowski,
     https://blog.cloudflare.com/introducing-the-bpf-tools/

1. May 2014,
     BPF - the forgotten bytecode,
     Marek Majkowski,
     https://blog.cloudflare.com/bpf-the-forgotten-bytecode/

Talks
-----

The following (incomplete) list includes talks and conference papers
related to BPF and XDP:

44. May 2017,
     PyCon 2017, Portland,
     Executing python functions in the linux kernel by transpiling to bpf,
     Alex Gartrell,
     https://www.youtube.com/watch?v=CpqMroMBGP4

43. May 2017,
     gluecon 2017, Denver,
     Cilium + BPF: Least Privilege Security on API Call Level for Microservices,
     Dan Wendlandt,
     http://gluecon.com/#agenda

42. May 2017,
     Lund Linux Con, Lund,
     XDP - eXpress Data Path,
     Jesper Dangaard Brouer,
     http://people.netfilter.org/hawk/presentations/LLC2017/XDP_DDoS_protecting_LLC2017.pdf

41. May 2017,
     Polytechnique Montreal,
     Trace Aggregation and Collection with eBPF,
     Suchakra Sharma,
     http://step.polymtl.ca/~suchakra/eBPF-5May2017.pdf

40. Apr 2017,
     DockerCon, Austin,
     Cilium - Network and Application Security with BPF and XDP,
     Thomas Graf,
     https://www.slideshare.net/ThomasGraf5/dockercon-2017-cilium-network-and-application-security-with-bpf-and-xdp

39. Apr 2017,
     NetDev 2.1, Montreal,
     XDP Mythbusters,
     David S. Miller,
     https://www.netdevconf.org/2.1/slides/apr7/miller-XDP-MythBusters.pdf

38. Apr 2017,
     NetDev 2.1, Montreal,
     Droplet: DDoS countermeasures powered by BPF + XDP,
     Huapeng Zhou, Doug Porter, Ryan Tierney, Nikita Shirokov,
     https://www.netdevconf.org/2.1/slides/apr6/zhou-netdev-xdp-2017.pdf

37. Apr 2017,
     NetDev 2.1, Montreal,
     XDP in practice: integrating XDP in our DDoS mitigation pipeline,
     Gilberto Bertin,
     https://www.netdevconf.org/2.1/slides/apr6/bertin_Netdev-XDP.pdf

36. Apr 2017,
     NetDev 2.1, Montreal,
     XDP for the Rest of Us,
     Andy Gospodarek, Jesper Dangaard Brouer,
     https://www.netdevconf.org/2.1/slides/apr7/gospodarek-Netdev2.1-XDP-for-the-Rest-of-Us_Final.pdf

35. Mar 2017,
     SCALE15x, Pasadena,
     Linux 4.x Tracing: Performance Analysis with bcc/BPF,
     Brendan Gregg,
     https://www.slideshare.net/brendangregg/linux-4x-tracing-performance-analysis-with-bccbpf

34. Mar 2017,
     XDP Inside and Out,
     David S. Miller,
     https://github.com/iovisor/bpf-docs/raw/master/XDP_Inside_and_Out.pdf

33. Mar 2017,
     OpenSourceDays, Copenhagen,
     XDP - eXpress Data Path, Used for DDoS protection,
     Jesper Dangaard Brouer,
     https://github.com/iovisor/bpf-docs/raw/master/XDP_Inside_and_Out.pdf

32. Mar 2017,
     source{d}, Infrastructure 2017, Madrid,
     High-performance Linux monitoring with eBPF,
     Alfonso Acosta,
     https://www.youtube.com/watch?v=k4jqTLtdrxQ

31. Feb 2017,
     FOSDEM 2017, Brussels,
     Stateful packet processing with eBPF, an implementation of OpenState interface,
     Quentin Monnet,
     https://fosdem.org/2017/schedule/event/stateful_ebpf/

30. Feb 2017,
     FOSDEM 2017, Brussels,
     eBPF and XDP walkthrough and recent updates,
     Daniel Borkmann,
     http://borkmann.ch/talks/2017_fosdem.pdf

29. Feb 2017,
     FOSDEM 2017, Brussels,
     Cilium - BPF & XDP for containers,
     Thomas Graf,
     https://fosdem.org/2017/schedule/event/cilium/

28. Jan 2017,
     linuxconf.au, Hobart,
     BPF: Tracing and more,
     Brendan Gregg,
     https://www.slideshare.net/brendangregg/bpf-tracing-and-more

27. Dec 2016,
     USENIX LISA 2016, Boston,
     Linux 4.x Tracing Tools: Using BPF Superpowers,
     Brendan Gregg,
     https://www.slideshare.net/brendangregg/linux-4x-tracing-tools-using-bpf-superpowers

26. Nov 2016,
     Linux Plumbers, Santa Fe,
     Cilium: Networking & Security for Containers with BPF & XDP,
     Thomas Graf,
     http://www.slideshare.net/ThomasGraf5/clium-container-networking-with-bpf-xdp

25. Nov 2016,
     OVS Conference, Santa Clara,
     Offloading OVS Flow Processing using eBPF,
     William (Cheng-Chun) Tu,
     http://openvswitch.org/support/ovscon2016/7/1120-tu.pdf

24. Oct 2016,
     One.com, Copenhagen,
     XDP - eXpress Data Path, Intro and future use-cases,
     Jesper Dangaard Brouer,
     http://people.netfilter.org/hawk/presentations/xdp2016/xdp_intro_and_use_cases_sep2016.pdf

23. Oct 2016,
     Docker Distributed Systems Summit, Berlin,
     Cilium: Networking & Security for Containers with BPF & XDP,
     Thomas Graf,
     http://www.slideshare.net/Docker/cilium-bpf-xdp-for-containers-66969823

22. Oct 2016,
     NetDev 1.2, Tokyo,
     Data center networking stack,
     Tom Herbert,
     http://netdevconf.org/1.2/session.html?tom-herbert

21. Oct 2016,
     NetDev 1.2, Tokyo,
     Fast Programmable Networks & Encapsulated Protocols,
     David S. Miller,
     http://netdevconf.org/1.2/session.html?david-miller-keynote

20. Oct 2016,
     NetDev 1.2, Tokyo,
     XDP workshop - Introduction, experience, and future development,
     Tom Herbert,
     http://netdevconf.org/1.2/session.html?herbert-xdp-workshop

19. Oct 2016,
     NetDev1.2, Tokyo,
     The adventures of a Suricate in eBPF land,
     Eric Leblond,
     http://netdevconf.org/1.2/slides/oct6/10_suricata_ebpf.pdf

18. Oct 2016,
     NetDev1.2, Tokyo,
     cls_bpf/eBPF updates since netdev 1.1,
     Daniel Borkmann,
     http://borkmann.ch/talks/2016_tcws.pdf

17. Oct 2016,
     NetDev1.2, Tokyo,
     Advanced programmability and recent updates with tc’s cls_bpf,
     Daniel Borkmann,
     http://borkmann.ch/talks/2016_netdev2.pdf
     http://www.netdevconf.org/1.2/papers/borkmann.pdf

16. Oct 2016,
     NetDev 1.2, Tokyo,
     eBPF/XDP hardware offload to SmartNICs,
     Jakub Kicinski, Nic Viljoen,
     http://netdevconf.org/1.2/papers/eBPF_HW_OFFLOAD.pdf

15. Aug 2016,
     LinuxCon, Toronto,
     What Can BPF Do For You?,
     Brenden Blanco,
     https://events.linuxfoundation.org/sites/events/files/slides/iovisor-lc-bof-2016.pdf

14. Aug 2016,
     LinuxCon, Toronto,
     Cilium - Fast IPv6 Container Networking with BPF and XDP,
     Thomas Graf,
     https://www.slideshare.net/ThomasGraf5/cilium-fast-ipv6-container-networking-with-bpf-and-xdp

13. Aug 2016,
     P4, EBPF and Linux TC Offload,
     Dinan Gunawardena, Jakub Kicinski,
     https://de.slideshare.net/Open-NFP/p4-epbf-and-linux-tc-offload

12. Jul 2016,
     Linux Meetup, Santa Clara,
     eXpress Data Path,
     Brenden Blanco,
     http://www.slideshare.net/IOVisor/express-data-path-linux-meetup-santa-clara-july-2016

11. Jul 2016,
     Linux Meetup, Santa Clara,
     CETH for XDP,
     Yan Chan, Yunsong Lu,
     http://www.slideshare.net/IOVisor/ceth-for-xdp-linux-meetup-santa-clara-july-2016

10. May 2016,
     P4 workshop, Stanford,
     P4 on the Edge,
     John Fastabend,
     https://schd.ws/hosted_files/2016p4workshop/1d/Intel%20Fastabend-P4%20on%20the%20Edge.pdf

9. Mar 2016,
    Performance @Scale 2016, Menlo Park,
    Linux BPF Superpowers,
    Brendan Gregg,
    https://www.slideshare.net/brendangregg/linux-bpf-superpowers

8. Mar 2016,
    eXpress Data Path,
    Tom Herbert, Alexei Starovoitov,
    https://github.com/iovisor/bpf-docs/raw/master/Express_Data_Path.pdf

7. Feb 2016,
    NetDev1.1, Seville,
    On getting tc classifier fully programmable with cls_bpf,
    Daniel Borkmann,
    http://borkmann.ch/talks/2016_netdev.pdf
    http://www.netdevconf.org/1.1/proceedings/papers/On-getting-tc-classifier-fully-programmable-with-cls-bpf.pdf

6. Jan 2016,
    FOSDEM 2016, Brussels,
    Linux tc and eBPF,
    Daniel Borkmann,
    http://borkmann.ch/talks/2016_fosdem.pdf

5. Oct 2015,
    LinuxCon Europe, Dublin,
    eBPF on the Mainframe,
    Michael Holzheu,
    https://events.linuxfoundation.org/sites/events/files/slides/ebpf_on_the_mainframe_lcon_2015.pdf

4. Aug 2015,
    Tracing Summit, Seattle,
    LLTng's Trace Filtering and beyond (with some eBPF goodness, of course!),
    Suchakra Sharma,
    https://github.com/iovisor/bpf-docs/raw/master/ebpf_excerpt_20Aug2015.pdf

3. Jun 2015,
    LinuxCon Japan, Tokyo,
    Exciting Developments in Linux Tracing,
    Elena Zannoni,
    https://events.linuxfoundation.org/sites/events/files/slides/tracing-linux-ezannoni-linuxcon-ja-2015_0.pdf

2. Feb 2015,
    Collaboration Summit, Santa Rosa,
    BPF: In-kernel Virtual Machine,
    Alexei Starovoitov,
    https://events.linuxfoundation.org/sites/events/files/slides/bpf_collabsummit_2015feb20.pdf

1. Feb 2015,
    NetDev 0.1, Ottawa,
    BPF: In-kernel Virtual Machine,
    Alexei Starovoitov,
    http://netdevconf.org/0.1/sessions/15.html

0. Feb 2014,
    DevConf.cz, Brno,
    tc and cls_bpf: lightweight packet classifying with BPF,
    Daniel Borkmann,
    http://borkmann.ch/talks/2014_devconf.pdf

Further Documents
-----------------

- Dive into BPF: a list of reading material,
  Quentin Monnet
  (https://qmonnet.github.io/whirl-offload/2016/09/01/dive-into-bpf/)
- XDP - eXpress Data Path,
  Jesper Dangaard Brouer
  (https://prototype-kernel.readthedocs.io/en/latest/networking/XDP/index.html)
