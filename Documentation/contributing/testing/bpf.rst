.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _bpf_testing:

********************************
BPF Unit and Integration Testing
********************************

Our BPF datapath has its own test framework, which allows us to write unit and integration tests that 
verify that our BPF code works as intended, independently from the other Cilium components. The 
framework uses the ``BPF_PROG_RUN`` feature to run eBPF programs in the kernel without attaching
them to actual hooks.

The framework is designed to allow datapath developers to quickly write tests
for the code they are working on. The tests themselves are fully written in C to minimize context
switching. Tests pass results back to the framework which will outputs the results in Go test output,
for optimal integration with CI and other tools.

Running tests
=============

To run the tests in your local environment, execute the following command from the project root:

.. code-block:: shell-session

    $ make -C test run_bpf_tests

The output is verbose by default. Verbose mode can be disabled by setting the ``V`` option to ``0``:

.. code-block:: shell-session

    $ make -C test run_bpf_tests V=0

.. note:: 

    Running BPF tests only works on Linux machines and requires admin privileges.
    The makefile uses sudo implicitly and may prompt you for credentials.

Writing tests
=============

All BPF tests live in the ``bpf/tests`` directory. All ``.c`` files in this directory are assumed to
contain BPF test programs which can be independently compiled, loaded, and executed using 
``BPF_PROG_RUN``. All files in this directory are automatically picked up, so all you have to do is 
create a new ``.c`` file and start writing. All other files like ``.h`` files are ignored and can be
used for sharing code for example.

Each ``.c`` file must at least have one ``CHECK`` program. The ``CHECK`` macro replaces the ``SEC`` which is
typically used in BPF programs. The ``CHECK`` macro takes two arguments, the first being the program
type (for example ``xdp`` or ``tc``. See `the list of recognized types in the Go library
<https://github.com/cilium/ebpf/blob/49ebb13083886fc350167f2cde067e094a2b5037/elf_reader.go#L1074>`__),
the second being the name of the test which will appear in the output. All macros are defined in 
``bpf/tests/common.h``, so all programs should start by including this file: ``#include "common.h"``.

Each ``CHECK`` program should start with ``test_init()`` and end with ``test_finish()``, ``CHECK`` programs
will return implicitly with the result of the test, a user doesn't need to add ``return`` statements
to the code manually. A test will PASS if it reaches ``test_finish()``, unless it is marked as 
failed(``test_fail()``, ``test_fail_now()``, ``test_fatal()``) or skipped(``test_skip()``, ``test_skip_now()``).

The name of the function has no significance for the tests themselves. The function names are still
used as indicators in the kernel (at least the first 15 chars), used to populate tail call maps, 
and should be unique for the purposes of compilation.

.. code-block:: c
    
    #include "common.h"

    CHECK("xdp", "nodeport-lb4")
    int nodeportLB4(struct __ctx_buff *ctx)
    {
	    test_init();

        /* ensure preconditions are met */
        /* call the functions you would like to test */
        /* check that everything works as expected */
        
        test_finish();
    }

Sub-tests
---------

Each ``CHECK`` program may contain sub-tests, each of which has its own test status. A sub-test is
created with the ``TEST`` macro like so:

.. code-block:: c

    #include "common.h"

    #include <bpf/ctx/xdp.h>
    #include <lib/jhash.h>
    #include "bpf/section.h"

    CHECK("xdp", "jhash")
    int bpf_test(__maybe_unused struct xdp_md *ctx)
    {
        test_init();

        TEST("Non-zero", {
            unsigned int hash = jhash_3words(123, 234, 345, 456);

            if (hash != 2698615579)
                test_fatal("expected '2698615579' got '%lu'", hash);
        });

        TEST("Zero", {
            unsigned int hash = jhash_3words(0, 0, 0, 0);

            if (hash != 459859287)
                test_fatal("expected '459859287' got '%lu'", hash);
        });

        test_finish();
    }

Since all sub-tests are part of the same BPF program they are executed consecutively in one 
``BPF_PROG_RUN`` invocation and can share setup code which can improve run speed and reduce code duplication.
The name passed to the ``TEST`` macro for each sub-test serves to self-document the steps and makes it easier to spot what part of a test fails.

Integration tests
-----------------

Writing tests for a single function or small group of functions should be fairly straightforward, 
only requiring a ``CHECK`` program. Testing functionality across tail calls requires an additional step: 
given that the program does not return to the ``CHECK`` function after making a tail call, we can't check whether it was successful.

The workaround is to use ``PKTGEN`` and ``SETUP`` programs in addition to a ``CHECK`` program.
These programs will run before the ``CHECK`` program with the same name.
Intended usage is that the ``PKGTEN`` program builds a BPF context (for example fill a ``struct __sk_buff`` for TC programs), and passes it on
to the ``SETUP`` program, which performs further setup steps (for example fill a BPF map). The two-stage pattern is needed so that ``BPF_PROG_RUN`` gets
invoked with the actual packet content (and for example fills ``skb->protocol``).

The BPF context is then passed to the ``CHECK`` program, which can inspect the result. By executing the test setup and executing the tail
call in ``SETUP`` we can execute complete programs.  The return code of the ``SETUP`` program is prepended as a ``u32`` to the start of the
packet data passed to ``CHECK``, meaning that the ``CHECK`` program will find the actual packet data at ``(void *)data + 4``.

This is an abbreviated example showing the key components:

.. code-block:: c
    
    #include "common.h"

    #include "bpf/ctx/xdp.h"
    #include "bpf_xdp.c"

    struct {
        __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
        __uint(key_size, sizeof(__u32));
        __uint(max_entries, 2);
        __array(values, int());
    } entry_call_map __section(".maps") = {
        .values = {
            [0] = &cil_xdp_entry,
        },
    };

    PKTGEN("xdp", "l2_example")
    int test1_pktgen(struct __ctx_buff *ctx)
    {
        /* Create room for our packet to be crafted */
        unsigned int data_len = ctx->data_end - ctx->data;
        int offset = offset = sizeof(struct ethhdr) - data_len;
        bpf_xdp_adjust_tail(ctx, offset);

        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;

        if (data + sizeof(struct ethhdr) > data_end)
            return TEST_ERROR;

        /* Writing just the L2 header for brevity */
        struct ethhdr l2 = {
            .h_source = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
            .h_dest = {0x12, 0x23, 0x34, 0x45, 0x56, 0x67},
            .h_proto = bpf_htons(ETH_P_IP)
        };
        memcpy(data, &l2, sizeof(struct ethhdr));

        return 0;
    }

    SETUP("xdp", "l2_example")
    int test1_setup(struct __ctx_buff *ctx)
    {
        /* OMITTED setting up map state */

        /* Jump into the entrypoint */
        tail_call_static(ctx, &entry_call_map, 0);
        /* Fail if we didn't jump */
        return TEST_ERROR;
    }

    CHECK("xdp", "l2_example")
    int test1_check(__maybe_unused const struct __ctx_buff *ctx)
    {
        test_init();

        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;

        if (data + sizeof(__u32) > data_end)
            test_fatal("status code out of bounds");

        __u32 *status_code = data;

        if (*status_code != XDP_TX)
            test_fatal("status code != XDP_TX");

        data += sizeof(__u32);

        if (data + sizeof(struct ethhdr) > data_end)
            test_fatal("ctx doesn't fit ethhdr");

        struct ethhdr *l2 = data;

        data += sizeof(struct ethhdr);

        if (memcmp(l2->h_source, fib_smac, sizeof(fib_smac)))
            test_fatal("l2->h_source != fib_smac");

        if (memcmp(l2->h_dest, fib_dmac, sizeof(fib_dmac)))
            test_fatal("l2->h_dest != fib_dmac");

        if (data + sizeof(struct iphdr) > data_end)
            test_fatal("ctx doesn't fit iphdr");

        test_finish();
    }

Function reference
------------------

* ``test_log(fmt, args...)`` - writes a log message. The conversion specifiers supported by *fmt* are the same as for
  ``bpf_trace_printk()``. They are **%d**, **%i**, **%u**, **%x**, **%ld**, **%li**, **%lu**, **%lx**, **%lld**, **%lli**, 
  **%llu**, **%llx**. No modifier (size of field, padding with zeroes, etc.) is available.

* ``test_fail()`` - marks the current test or sub-test as failed but will continue execution.

* ``test_fail_now()`` - marks the current test or sub-test as failed and will stop execution of the 
  test or sub-test (If called in a sub-test, the other sub-tests will still run).

* ``test_fatal(fmt, args...)`` - writes a log and then calls ``test_fail_now()``

* ``assert(stmt)`` - asserts that the statement within is true and call ``test_fail_now()`` otherwise.
  ``assert`` will log the file and line number of the assert statement.

* ``test_skip()`` - marks the current test or sub-test as skipped but will continue execution.

* ``test_skip_now()`` - marks the current test or sub-test as skipped and will stop execution of the 
  test or sub-test (If called in a sub-test, the other sub-tests will still run).

* ``test_init()`` - initializes the internal state for the test and must be called before any of the 
  functions above can be called.

* ``test_finish()`` - submits the results and returns from the current function.

.. warning::
    Functions that halt the execution (``test_fail_now()``, ``test_fatal()``, ``test_skip_now()``) can't be
    used within both a sub-test (``TEST``) and ``for``, ``while``, or ``switch/case`` blocks since they use the ``break`` keyword to stop a
    sub-test. These functions can still be used from within ``for``, ``while`` and ``switch/case`` blocks if no 
    sub-tests are used, because in that case the flow interruption happens via ``return``.

Function mocking
----------------

Being able to mock out a function is a great tool to have when creating tests for a number of 
reasons. You might for example want to test what happens if a specific function returns an error 
to see if it is handled gracefully. You might want to proxy function calls to record if the function
under test actually called specific dependencies. Or you might want to test code that uses helpers
which rely on a state we can't set in BPF, like the routing table.

Mocking is easy with this framework:

1. Create a function with a unique name and the same signature as the function it is replacing.

2. Create a macro with the exact same name as the function we want to replace and point it to the
   function created in step 1. For example ``#define original_function our_mocked_function```

3. Include the file which contains the definition we are replacing.

The following example mocks out the fib_lookup helper call and replaces it with our
mocked version, since we don't actually have routes for the IPs we want to test:

.. code-block:: c

    #include "common.h"

    #include "bpf/ctx/xdp.h"

    #define fib_lookup mock_fib_lookup

    static const char fib_smac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02};
    static const char fib_dmac[6] = {0x13, 0x37, 0x13, 0x37, 0x13, 0x37};

    long mock_fib_lookup(__maybe_unused void *ctx, struct bpf_fib_lookup *params,
                __maybe_unused int plen, __maybe_unused __u32 flags)
    {
        memcpy(params->smac, fib_smac, sizeof(fib_smac));
        memcpy(params->dmac, fib_dmac, sizeof(fib_dmac));
        return 0;
    }

    #include "bpf_xdp.c"
    #include "lib/nodeport.h"

Limitations
-----------

For all its benefits there are some limitations to this way of testing:

* Code must pass the verifier, so our setup and test code has to obey the same rules as other BPF
  programs. A side effect is that it automatically guarantees that all code that passes will also
  load. The biggest concern is the complexity limit on older kernels, this can be somewhat mitigated
  by separating heavy setup work into its own ``SETUP`` program and optionally tail calling into the 
  code to be tested, to ensure the testing harness doesn't push us over the complexity limit.

* Test functions like ``test_log()``, ``test_fail()``, ``test_skip()`` can only be executed within the 
  scope of the main program or a ``TEST``. These functions rely on local variables set by ``test_init()`` 
  and will produce errors when used in other functions. 
  
* Functions that halt the execution (``test_fail_now()``, ``test_fatal()``, ``test_skip_now()``) can't be
  used within both a sub-test (``TEST``) and ``for``, ``while``, or ``switch/case`` blocks since they use the ``break`` keyword to stop a
  sub-test. These functions can still be used from within ``for``, ``while`` and ``switch/case`` blocks if no 
  sub-tests are used, because in that case the flow interruption happens via ``return``.

* Sub-test names can't use more than 127 characters.

* Log messages can't use more than 127 characters and have no more than 12 arguments.
