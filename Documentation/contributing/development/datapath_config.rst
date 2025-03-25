.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _dpconfig:

Configuring the Datapath
========================

Introduction
~~~~~~~~~~~~

In order for the Cilium datapath to function, it needs access to configuration
data such as feature flags, addresses, timeouts, security IDs and all sorts of
tunables and user configuration. These values are provided by the agent at the
time of loading the BPF program. This page outlines the configuration mechanism,
some recommendations, how to migrate legacy configuration, as well as practical
examples.

Getting Started
~~~~~~~~~~~~~~~

First, let's look at a practical example to illustrate the configuration API and
see the configuration process in action. This will help you understand how to
declare, assign, and use configuration variables effectively in the Cilium
datapath.

Declaring C Variable
^^^^^^^^^^^^^^^^^^^^

To start off, let's take a look at a straightforward example of a configuration
value used in the datapath. This is an example from
``bpf/include/bpf/config/lxc.h``, included by ``bpf_lxc.c``:

.. code-block:: c

  DECLARE_CONFIG(__u16, endpoint_id, "The endpoint's security ID")

This invokes the ``DECLARE_CONFIG`` macro, which declares the 16-bit unsigned
integer config value named ``endpoint_id``, followed by a description. We'll see
why the description is useful later on.

With our variable declared, ``make`` the ``bpf/`` directory to rebuild the
datapath and run ``dpgen`` to generate Go code:

.. code-block:: bash

  make -C bpf -j$(nproc)

This will emit our variable to one of the Go config scaffoldings in the
``pkg/datapath/config`` Go package.

Wiring up Go Values
^^^^^^^^^^^^^^^^^^^

One of the files in package ``config`` will now contain a new struct field that
can be populated at BPF load time.

.. code-block:: go

  type BPFLXC struct {
    ...
    // The endpoint's security ID.
    EndpointID uint16 `config:"endpoint_id"`
    ...
  }

As shown in the preceding snippet, the new struct field carries our helpful
comment we provided in the C code and refers to the ``endpoint_id`` variable we
declared.

.. note::

  At the time of writing, populating Go configuration scaffolding still mostly
  happens in ``pkg/datapath/loader`` and is scattered between a few places. The
  goal is to create StateDB tables for each configuration object. These can be
  managed from Hive Cells and automatically trigger a reload of the necessary
  BPF programs when any of the values change. This document will be updated
  along with these changes.

Now, we need to wire up the field with an actual value. Depending on which
object you're adding configuration to and depending on whether the value is
"node configuration" (more below) or object-specific, you may need to look in
different places. For example, adding a value to ``bpf_lxc.c`` like in this
example, the value is typically set in ``endpointRewrites()``:

.. code-block:: go

  func endpointRewrites(...) ... {
    ...
    cfg.InterfaceIfindex = uint32(ep.GetIfIndex())
    ...
  }

.. warning::

  This plumbing needs to be done for every object that needs access to the
  variable! For example, if you declare a variable in a header common to both
  ``bpf_lxc.c`` and ``bpf_host.c``, you'll need to make sure the agent supplies
  the value to both structs.

If this document no longer matches the codebase, grep around for uses of the
various structs and their fields, and extend the existing code. Over time, Hive
Cells will be able to write to these structs using StateDB tables.

Reading the Variable in C
^^^^^^^^^^^^^^^^^^^^^^^^^

We've declared our global config variable. We've generated Go code and wired up
a value from the agent. Now, we need to put the variable to use!

In datapath BPF code, we can refer to it using the ``CONFIG()`` macro. This
macro resolves to a special variable name representing our configuration value,
which could change in the future. The macro is there to avoid cross-cutting code
changes if we ever need to make changes here.

.. note::

  The variable is not a compile-time constant, so it cannot be used to control
  things like BPF map sizes or to initialize other global ``const`` variables at
  compile time.

.. code-block:: C

  CONFIG(endpoint_id)

Use the macro like you would typically use a variable:

.. code-block:: c

  __u16 endpoint_id = CONFIG(endpoint_id);

or in a branch:

.. code-block:: c

  if (CONFIG(endpoint_id) != 0) {
    ...
  }

Node Configuration
~~~~~~~~~~~~~~~~~~

.. warning::

  Historically, most of the agent's configuration was presented to the datapath
  as "node configuration" (in ``node_config.h``), but this pattern is
  discouraged going forward and may go away at some point in the future. More on
  this in :ref:`guidelines`.

To make migration from ``#define``-style configuration more straightforward,
we've kept the concept of node configuration, albeit with runtime-provided
values instead of ``#ifdef``.

Node configuration can be declared in ``bpf/include/bpf/config/node.h``:

.. code-block:: c

  NODE_CONFIG(__u64, foo, "The foo value")

This will show up in the Go scaffolding as:

.. code-block:: go

   type Node struct {
      // The foo value.
      Foo uint64 `config:"foo"`
    }

Populate it in the agent through ``pkg/datapath/loader.nodeConfig()``:

.. code-block:: go

  func nodeConfig(lnc *datapath.LocalNodeConfiguration) config.Node {
    ...
    node.Foo = 42
    ...
  }

It behaves identically with regards to ``CONFIG()``.

.. _guidelines:

Guidelines and Recommendations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A few guiding principles:

- Avoid dead code in the form of variables that are never set by the agent. For
  example, if only ``bpf_lxc.c`` uses your variable, don't put it in a shared
  header across multiple BPF objects. To share types with other objects, put
  those in a separate header instead.
- Declare variables close to where they're used, e.g. in header files
  implementing a feature.
- Avoid conditional ``#include`` statements.

Use the following procedure to determine where to declare your configuration:

1. For new features, use ``DECLARE_CONFIG()`` in the header implementing your
   feature. Only import the header in the BPF object(s) where the feature is
   utilized.
2. For new config in existing features, ``DECLARE_CONFIG()`` as close as
   possible to the code that consumes it.
3. For porting over node configuration from ``node_config.h``
   (``WriteNodeConfig``), try narrowing down where the config is used and see if
   it can use ``DECLARE_CONFIG()`` in a header imported by a small number of BPF
   objects instead. Refactoring is worth it here, since it avoids dead code in
   objects that don't use the node config.
4. If none of the above cases apply, use ``NODE_CONFIG()``.

.. _defaults:

Defaults
~~~~~~~~

To assign a default value other than 0 to a configuration variable directly from
C, the ``ASSIGN_CONFIG()`` macro can be used after declaring the variable. This
can be useful for setting sane defaults that will automatically apply even when
the agent doesn't supply a value.

For example, the agent uses this for device MTU:

.. code-block:: c

  DECLARE_CONFIG(__u16, device_mtu, "MTU of the device the bpf program is attached to")
  ASSIGN_CONFIG(__u16, device_mtu, MTU)

.. warning::

  ``ASSIGN_CONFIG()`` can only be used once per variable per compilation unit.
  This makes it so the variable cannot be overridden from tests without a
  workaround, so use sparingly. See :ref:`testing` for more details.

.. _testing:

Testing
~~~~~~~

When writing tests, you may need to override configuration values to test
different code paths. This can be done by using the ``ASSIGN_CONFIG()`` macro in
a test file as described in :ref:`defaults` after importing the main object
under test, e.g. ``bpf_lxc.c``. See the test suite itself for the most
up-to-date examples.

Note that there are some restrictions, primarily that the literal passed to
``ASSSIGN_CONFIG()`` must be compile-time constant, and can't e.g. be the name
of another variable.

Occasionally, you may need to override a config that already has a default value
set using ``ASSIGN_CONFIG()``, in which case a workaround is needed:

.. code-block:: c

  #ifndef OVERRIDABLE_CONFIG
  DECLARE_CONFIG(__u8, overridable, "Config with a default and an override from tests")
  ASSIGN_CONFIG(__u8, overridable, 42)
  #define OVERRIDABLE_CONFIG CONFIG(overridable)
  #endif

Then, from the test file, set ``#define OVERRIDABLE_CONFIG`` before including
the object under test to make the override take precedence.

.. code-block:: c

  #define OVERRIDABLE_CONFIG 1337
  #include "bpf_lxc.c"

This is somewhat surprising, so use sparingly and consider refactoring the code
to avoid the need for this.

Known Limitations
~~~~~~~~~~~~~~~~~

- Runtime-based configuration cannot currently be set during verifier tests.
  This means that if you have a branch behind a (boolean) config, it will
  currently not be evaluated by the verifier, and there may be latent verifier
  errors that pop up when enabled through agent configuration. However, with the
  new configuration mechanism, we can now fully automate testing all
  permutations of config flags, without having to maintain them manually going
  forward. Hold off on migrating ``ENABLE_`` defines until this is resolved.
- Generating Go scaffolding for struct variables is not yet supported.

Background
~~~~~~~~~~

Historically, configuration was fed into the datapath using ``#define``
statements generated at runtime, with sections of optional code cordoned off by
``#ifdef`` and similar mechanisms. This has served us well over the years, but
with the increasing complexity of the agent and the datapath, it has become
clear that we need a more structured and maintainable way to configure the
datapath.

Linux kernels 5.2 and later support read-only maps to store config data that
cannot be changed after the kernel verified the program. If these values are
used in branches, the verifier can then perform dead code elimination,
eliminating branches it deems unreachable. This minimizes the amount of work the
verifier needs to do in subsequent verification steps and ensures the BPF
program image is as lean as possible.

This also means we no longer need to conditionally compile out parts of code we
don't need, so we can adopt an approach where the datapath's BPF code is built
and embedded into the agent at compile time. This, in turn, means we no longer
need to ship LLVM with the agent (maybe you've heard of the term
``clang-free``), reducing the size of the agent container image and
significantly cutting down on agent startup time and CPU usage. Endpoints will
also regenerate faster during configuration changes.
