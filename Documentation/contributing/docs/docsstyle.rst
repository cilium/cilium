.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

*******************
Documentation Style
*******************

.. |RST| replace:: reStructuredText

Here are some guidelines and best practices for contributing to Cilium's
documentation. They have several objectives:

- Ensure that the documentation is rendered in the best possible way (in
  particular for code blocks).

- Make the documentation easy to maintain and extend.

- Help keep a consistent style throughout the documentation.

See also :ref:`the documentation for testing <testing-documentation>` for
instructions on how to preview documentation changes.

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

Titles
------

Prefer title case (capital letters on most words of the title) rather than
sentence case for titles.
See this link if necessary: https://titlecaseconverter.com/.

Body
----

Wrap the lines for long sentences or paragraphs. There is no fixed convention
on the length of lines, but targeting a width of about 80 characters should be
safe in most circumstances.

Code Blocks
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
