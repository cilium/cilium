.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _docs_style_guide:

*******************
Documentation style
*******************

.. |RST| replace:: reStructuredText

Here are some guidelines and best practices for contributing to Cilium's
documentation. They have several objectives:

- Ensure that the documentation is rendered in the best possible way (in
  particular for code blocks).

- Make the documentation easy to maintain and extend.

- Help keep a consistent style throughout the documentation.

- In the end, provide a better experience to users, and help them find the
  information they need.

See also :ref:`the documentation for testing <testing-documentation>` for
instructions on how to preview documentation changes.

General considerations
----------------------

Write in US English.
For example, use "prioritize" instead of ":spelling:ignore:`prioritise`" and
"color" instead of ":spelling:ignore:`colour`".

Maintain a consistent style with the rest of the documentation when possible,
or at least with the rest of the updated page.

Omit hyphens when possible. For example, use "load balancing" instead of
"load-balancing".

Header
------

Use the following header when adding new files to the Documentation.

.. code-block:: rst

  .. only:: not (epub or latex or html)

          WARNING: You are looking at unreleased Cilium documentation.
          Please use the official rendered version released here:
          https://docs.cilium.io

One exception is |RST| fragments that are supposed to be sourced from other
documentation files. Those do not need this header.

Headings
--------

Prefer sentence case (capital letter on first word) rather than
title case for all headings.

Body
----

Wrap the lines for long sentences or paragraphs. There is no fixed convention
on the length of lines, but targeting a width of about 80 characters should be
safe in most circumstances.

Capitalization
--------------

Follow `the section on capitalization for API objects`_ from the Kubernetes
style guide for when to (not) capitalize API objects. In particular:

    When you refer specifically to interacting with an API object, use
    `UpperCamelCase`_, also known as Pascal case.

And:

    When you are generally discussing an API object, use `sentence-style
    capitalization`_

For example, write "Gateway API", capitalized. Use "Gateway" when writing about
an API object as an entity, and "gateway" for a specific instance.

The following examples are correct::

    - Gateway API is a subproject of Kubernetes SIG Network.
    - Cilium is conformant to the Gateway API spec at version X.Y.Z.
    - In order to expose this service, create a Gateway to hold the listener configuration.
    - Traffic from the Internet passes through the gateway to get to the backend service.
    - Now that you have created the "foo" gateway, you need to create some Routes.

But the following examples are incorrect::

    - The implementation of gateway API
    - To create a gateway object, ...

.. _the section on capitalization for API objects: https://kubernetes.io/docs/contribute/style/style-guide/#use-upper-camel-case-for-api-objects
.. _UpperCamelCase: https://en.wikipedia.org/wiki/Camel_case
.. _sentence-style capitalization: https://docs.microsoft.com/en-us/style-guide/text-formatting/using-type/use-sentence-style-capitalization

.. _docs_style_code_blocks:

Code blocks
-----------

Code snippets and other literal blocks usually fall under one of those three
categories:

- They contain `substitution references`_ (for example: ``|SCM_WEB|``). In that
  case, always use the ``.. parsed-literal`` directive, otherwise the token
  will not be substituted.

  Prefer:

  .. code-block:: rst

    .. parsed-literal::

        $ kubectl create -f \ |SCM_WEB|\/examples/minikube/http-sw-app.yaml


  Avoid:

  .. code-block:: rst

    .. code-block:: shell-session

        $ kubectl create -f \ |SCM_WEB|\/examples/minikube/http-sw-app.yaml

- If the text is not a code snippet, but just some fragment that should be
  printed verbatim (for example, the unstructured output of a shell command),
  use the marker for `literal blocks`_ (``::``).

  Prefer:

  .. code-block:: rst

    See the output in ``dmesg``:

    ::

        [ 3389.935842] flen=6 proglen=70 pass=3 image=ffffffffa0069c8f from=tcpdump pid=20583
        [ 3389.935847] JIT code: 00000000: 55 48 89 e5 48 83 ec 60 48 89 5d f8 44 8b 4f 68

    See more output in ``dmesg``::

        [ 3389.935849] JIT code: 00000010: 44 2b 4f 6c 4c 8b 87 d8 00 00 00 be 0c 00 00 00
        [ 3389.935850] JIT code: 00000020: e8 1d 94 ff e0 3d 00 08 00 00 75 16 be 17 00 00

  Avoid:

  .. code-block:: rst

    See the output in ``dmesg``:

    .. parsed-literal::

        [ 3389.935842] flen=6 proglen=70 pass=3 image=ffffffffa0069c8f from=tcpdump pid=20583
        [ 3389.935847] JIT code: 00000000: 55 48 89 e5 48 83 ec 60 48 89 5d f8 44 8b 4f 68

  The reason is that because these snippets contain no code, there is no need
  to mark them as code or parsed literals. The former would tell Sphinx to
  attempt to apply syntax highlight, the second would tell it to look for |RST|
  markup to parse in the block.

- If the text contained code or structured output, use the ``.. code-block``
  directive. Do *not* use the ``.. code`` directive, which is slightly less
  flexible.

  Prefer:

  .. code-block:: rst

    .. code-block:: shell-session

        $ ls
        cilium
        $ cd cilium/

  Avoid:

  .. code-block:: rst

    .. parsed-literal::

        $ ls
        cilium
        $ cd cilium/

    .. code-block:: bash

        $ ls
        cilium
        $ cd cilium/

    .. code-block:: shell-session

        ls
        cilium
        cd cilium/

  The ``.. code-block`` directive should always take a language name as
  argument, for example: ``.. code-block:: yaml`` or ``.. code-block::
  shell-session``. The use of ``bash`` is possible but should be limited to
  Bash scripts. For any listing of shell commands, and in particular if the
  snippet mixes commands and their output, use ``shell-session``, which will
  bring the best coloration and may trigger the generation of the ``Copy
  commands`` button.

For snippets containing shell commands, in particular if they also contain the
output for those commands, use prompt symbols to prefix the commands. Use ``$``
for commands to run as a normal user, and ``#`` for commands to run with
administrator privileges. You may use ``sudo`` as an alternative way to mark
commands to run with privileges.

.. _substitution references: https://docutils.sourceforge.io/docs/ref/rst/restructuredtext.html#substitution-references
.. _literal blocks: https://docutils.sourceforge.io/docs/ref/rst/restructuredtext.html#literal-blocks

Links
-----

- Avoid using `embedded URIs`_ (```... <...>`__``), which make the document
  harder to read when looking at the source code of the documentation. Prefer
  to use `block-level hyperlink targets`_ (where the URI is not written
  directly in the sentence in the |RST| file, below the paragraph).

  Prefer:

  .. code-block:: rst

    See the `documentation for Cilium`_.

    Here is another link to `the same documentation <cilium documentation>`_.

    .. _documentation for Cilium:
    .. _cilium documentation: https://docs.cilium.io/en/latest/

  Avoid:

  .. code-block:: rst

    See the `documentation for Cilium <https://docs.cilium.io/en/latest/>`__.

- If using embedded URIs, use anonymous hyperlinks (```... <...>`__`` with two
  underscores, see the documentation for `embedded URIs`_) instead of named
  references (```... <...>`_``, note the single underscore).

  Prefer (but see previous item):

  .. code-block:: rst

    See the `documentation for Cilium <https://docs.cilium.io/en/latest/>`__.

  Avoid:

  .. code-block:: rst

    See the `documentation for Cilium <https://docs.cilium.io/en/latest/>`_.

.. _embedded URIs: https://docutils.sourceforge.io/docs/ref/rst/restructuredtext.html#embedded-uris-and-aliases
.. _block-level hyperlink targets: https://docutils.sourceforge.io/docs/ref/rst/restructuredtext.html#hyperlink-targets

Lists
-----

- Left-align the body of a list item with the text on the first line, after the 
  item symbol.

  Prefer:

  .. code-block:: rst

    - The text in this item
      wraps of several lines,
      with consistent indentation.

  Avoid:

  .. code-block:: rst

    - The text in this item
        wraps on several lines
        and the indent is not consistent
        with the first line.

- For enumerated lists, prefer auto-numbering with the ``#.`` marker rather
  than manually numbering the sections.

  Prefer:

  .. code-block:: rst

    #. First item
    #. Second item

  Avoid:

  .. code-block:: rst

    1. First item
    2. Second item

- Be consistent with periods at the end of list items. In general, omit periods
  from bulleted list items unless the items are complete sentences. But if one
  list item requires a period, use periods for all items.

  Prefer:

  .. code-block:: rst

    - This is one list item
    - This is another list item

  Avoid:

  .. code-block:: rst

    - This is one list item, period. We use punctuation.
    - This list item should have a period too, but doesn't

Callouts
--------

Use callouts effectively. For example, use the ``.. note::`` directive to
highlight information that helps users in a specific context. Do not use it to
avoid refactoring a section or paragraph.

For example, when adding information about a new configuration flag that
completes a feature, there is no need to append it as a note, given that it
does not require particular attention from the reader. Avoid the following:

.. parsed-literal::

    Blinking pods are easier to spot in the dark. Use feature flag
    \`\`--blinking-pods\`\` to make new pods blink twice when they launch. If
    you create blinking pods often, sunglasses may help protect your eyes.

    **\.. note::

        Use the flag \`\`--blinking-pods-blink-number\`\` to change the number
        of times pods blink on start-up.**

Instead, merge the new content with the existing paragraph:

.. parsed-literal::

    Blinking pods are easier to spot in the dark. Use feature flag
    \`\`--blinking-pods\`\` to make new pods blink when they launch. **By
    default, blinking pods blink twice, but you can use the flag
    \`\`--blinking-pods-blink-number\`\` to specify how many times they blink
    on start-up.** If you create blinking pods often, sunglasses may help
    protect your eyes.

Roles
-----

- We have a dedicated role for referencing Cilium GitHub issues, to reference
  them in a consistent fashion. Use it when relevant.

  Prefer:

  .. code-block:: rst

    See :gh-issue:`1234`.

  Avoid:

  .. code-block:: rst

    See `this GitHub issue <https://github.com/cilium/cilium/issues/1234>`__.

Common pitfalls
---------------

There are best practices for writing documentation; follow them. In general,
default to the `Kubernetes style guide`_, especially for `content best
practices`_. The following subsections cover the most common feedback given for
Cilium documentation Pull Requests.

Use active voice
~~~~~~~~~~~~~~~~

Prefer::

    Enable the flag.

Avoid::

    Ensure the flag is enabled.

Use present tense
~~~~~~~~~~~~~~~~~

Prefer::

    The service returns a response code.

Avoid::

    The service will return a response code.

Address the user as "you", not "we"
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Prefer::

    You can specify values to filter tags.

Avoid::

    We'll specify this value to filter tags.

Use plain, direct language
~~~~~~~~~~~~~~~~~~~~~~~~~~

Prefer::

    Always configure the bundle explicitly in production environments.

Avoid::

    It is recommended to always configure the bundle explicitly in production environments.

Write for good localization
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Assume that what you write will be localized with machine translation. Figures
of speech often localize poorly, as do idioms like "above" and "below".

Prefer::

    The following example
    To assist this process,

Avoid::

    The example below
    To give this process a boost,

Define abbreviations
~~~~~~~~~~~~~~~~~~~~

Define abbreviations when you first use them on a page.

Prefer::

    Certificate authority (CA)

Avoid::

    CA

Don't use Latin abbreviations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Prefer::

    - For example,
    - In other words,
    - by following the ...
    - and others

Avoid::

    - e.g.
    - i.e.
    - via
    - etc.

Spell words fully
~~~~~~~~~~~~~~~~~

Prefer::

    and

Avoid::

    &

.. _Kubernetes style guide: https://kubernetes.io/docs/contribute/style/style-guide/
.. _content best practices: https://kubernetes.io/docs/contribute/style/style-guide/#content-best-practices

Specific language
-----------------

Use specific language. Avoid words like "this" (as a pronoun) and "it" when
referring to concepts, actions, or process states. Be as specific as possible,
even if specificity seems overly repetitive. This requirement exists for two
reasons:

1. Indirect language assumes too much clarity on the part of the writer and too
   much understanding on the part of the reader.

2. Specific language is easier to review and easier to localize.

Words like "this" and "it" are indirect references. For example:

.. code-block:: rst

  Feature A requires all pods to be painted blue. This means that the Agent
  must apply its "paint" action to all pods. To achieve this, use the dedicated
  CLI invocation.

In the preceding paragraph, the word "this" indirectly references both an
inferred consequence ("this means") and a desired goal state ("to achieve
this"). Instead, be as specific as possible:

.. code-block:: rst

  Feature A requires all pods to be painted blue. Consequently, the Agent must
  apply its "paint" action to all pods. To make the Agent paint all pods blue,
  use the dedicated CLI invocation.

The following subsections contain more examples.

Use specific wording rather than vague wording
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Prefer::

    For each core, the Ingester attempts to spawn a worker pool.

Avoid::

    For each core, it attempts to spawn a worker pool.

Use specific instructions rather than vague instructions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Prefer::

    Set the annotation value to remote.

Avoid::

    Set it to remote.
