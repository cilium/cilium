.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _review_docs:

************************************
Reviewing for @cilium/docs-structure
************************************

What is @cilium/docs-structure?
===============================

Team `@cilium/docs-structure <docs-structure_team_>`_ is a GitHub team of
Cilium contributors who are responsible for maintaining the good state of the
project's documentation, by reviewing Pull Requests (PRs) that update the
documentation. Each time a non-draft PR touching files owned by the team opens,
GitHub automatically assigns one member of the team for review.

Open Cilium Pull Requests awaiting for reviews from @cilium/docs-structure are
`listed here <docs-structure_to_review_>`_.

To join the team, you must be a Cilium Reviewer. See `Cilium's Contributor
Ladder`_ for details on the requirements and the
application process.

.. _docs-structure_team: https://github.com/orgs/cilium/teams/docs-structure
.. _docs-structure_to_review: https://github.com/cilium/cilium/pulls?q=is%3Apr+is%3Aopen+draft%3Afalse+team-review-requested%3Acilium%2Fdocs-structure
.. _Cilium's Contributor Ladder: https://github.com/cilium/community/blob/main/CONTRIBUTOR-LADDER.md

Reviewing Pull Requests
=======================

This section describes some of the process and expectations for reviewing PRs
on behalf of cilium/docs-structure. Note that :ref:`the generic PR review
process for Committers <review_process>` applies, even though it is not
specific to documentation.

Technical contents
------------------

You are not expected to review the technical aspects of the documentation
changes in a PR. However, if you do have knowledge of the topic and if you find
some elements that are incorrect or missing, do flag them.

Documentation structure
-----------------------

One essential part of a review is to ensure that the contribution maintains a
coherent structure for the documentation. Ask yourself if the changes are
located on the right page, at the right place. This is especially important if
pages are added, removed, or shuffled around. If the addition is large,
consider whether the page needs to split. Consider also whether new text comes
with a satisfactory structure. For example, does it fit well with the
surrounding context, or did the author simply use a "note" box instead of
trying to integrate the new information to the relevant paragraph?

See also :ref:`the recommendations on documentation structure for contributors
<docs_structure_recommendations>`.

Specific items to look out for
------------------------------

Backport labels
~~~~~~~~~~~~~~~

See :ref:`the backport criteria for documentation changes
<backport_criteria_docs>`. Mark the PR for backports by setting the labels for
all supported branches to which the changes apply, that is to say, all
supported branches containing the parent features to which the modified
sections relate.

CODEOWNERS updates
~~~~~~~~~~~~~~~~~~

All documentation sources are assigned to cilium/docs-structure for review by
default. However, when a contributor creates a new page, consider whether it
should be covered by another team as well so that this other team can review
the technical aspects. If this is the case, ask the author to update the
CODEOWNERS file.

Beta disclaimer
~~~~~~~~~~~~~~~

When a feature is advertised as Beta in the PR, make sure that the author
clearly indicates the Beta status in the documentation, both by mentioning
"(Beta)" in the heading of the section for the feature and by including the
dedicated banner, as follows:

.. code-block:: rst

   .. include:: /Documentation/beta.rst

Upgrade notes
~~~~~~~~~~~~~

When the PR introduces new user-facing options, metrics, or behavior that
affects upgrades or downgrades, ensure that the author summarizes the changes
with a note in ``Documentation/operations/upgrade.rst``.

Completeness
~~~~~~~~~~~~

Make sure that new or updated content is complete, with no TODOs.

Auto-generated reference documents
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

When certain parts of the Cilium repository change, contributors may have to
update some auto-generated reference documents that are part of Cilium's
documentation, such as the command reference or the Helm reference. The CI
validates that these updates are present in the PR. If they are missing, you
may have to help contributors figure out what commands they need to run to
perform the updates. These commands are usually provided in the logs of the
GitHub workflows that failed to pass.

Spell checker exceptions
~~~~~~~~~~~~~~~~~~~~~~~~

The Documentation checks include running a spell checker. This spell checker
uses a file, ``Documentation/spelling_wordlist.txt``, containing a list of
spelling exceptions to ignore. Team cilium/docs-structure is the owner for this
file. Usually, there is not much feedback to provide on updates to the list of
exceptions. However, it's useful for reviewers to know that:

  - Entries are sorted alphabetically, with all words starting with uppercase
    letters coming before words starting with lowercase letters.
  - Entries in the list of exceptions must be spelled correctly.
  - Lowercase entries are case-insensitive for the spell checker, so reviewers
    should reject new entries with capital letters if the lowercase versions
    are already in the list.

Netlify preview
~~~~~~~~~~~~~~~

`Netlify`_ builds a new preview for each PR touching the documentation. You are
not expected to check the preview for each PR. However, if the PR contains
detailed formatting changes, such as nested blocks or directives, or changes to
tables or tabs, then it's good to validate that changes render as expected.
Also check the preview if you have a doubt as to the validity of the
reStructuredText (RST) mark-up that the author uses.

The list of checks on the PR page contains a link to the Netlify preview. If
the preview build failed, the link leads to the build logs.

.. _Netlify: https://www.netlify.com/?attr=homepage-modal

Formatting
----------

Read :ref:`Cilium's documentation style guide <docs_style_guide>`.

Flag poor formatting or obvious mistakes. The syntax for RST is not always
trivial and some contributors make mistakes, or they simply forget to use RST
and they employ Markdown mark-up instead. Make sure authors fix such issues.

Keep an eye on :ref:`code-blocks <docs_style_code_blocks>`: do they include RST
substitutions, and if so, do they use the right directive? If not, do they use
the right language?

Beyond that, the amount of time you spend on suggestions for improving
formatting is up to you.

Grammar and style
-----------------

Read :ref:`Cilium's documentation style guide <docs_style_guide>`.

Flag obvious grammar mistakes. Try to read the updated text as a user would.
Ask the contributors to revise any sentence that is too difficult to read or to
understand.

@cilium/docs-structure aims to keep the documentation clean, consistent, and in
a clear and comprehensible state. User experience must always be as good as
possible. To achieve this objective, Documentation updates must follow best
practices, such as the ones from the style guide. Reviewing PRs at sufficient
depth to flag all potential style improvements can be time consuming, so the
amount of effort that you put into style guidance is up to you.

There is no tooling in place to enforce particular style recommendations.

Documentation build
===================

The build framework
-------------------

Here are the main resources involved or related to Cilium's documentation build
framework:

  - :ref:`Instructions for building the documentation locally
    <testing-documentation>`
  - ``Documentation/Makefile``, ``Documentation/Dockerfile``,
    ``Documentation/check-build.sh``
  - Dependencies are in ``Documentation/requirements.txt``, which is generated
    from ``Documentation/requirements_min/requirements.txt``
  - The Sphinx theme we use is `our own fork <cilium_rtd_theme_>`_ of Read the
    Docs's theme

.. _cilium_rtd_theme: https://github.com/cilium/sphinx_rtd_theme

Relevant CI workflows
---------------------

Netlify preview
~~~~~~~~~~~~~~~

Documentation changes trigger the build of a new Netlify preview. If the build
fails, the PR authors or reviewers must investigate it. Ideally the author
should take care of this investigation, but in practice, contributors are not
always familiar with RST or with our build framework, so consider giving a
hand.

Documentation build
~~~~~~~~~~~~~~~~~~~

Same as the Netlify preview, the Documentation workflow runs on doc changes and
can raise missing updates on various generated pieces of documentation.

Checkpatch
~~~~~~~~~~

The Checkpatch workflow is part of the BPF tests and is not directly relevant
to documentation, but may raise some patch formatting issues, for example when
the commit title is too long. So it should run on doc-only PRs, like for any
other PR.

Integration tests
~~~~~~~~~~~~~~~~~

Integration tests, be it on Travis or on GitHub Actions, are the only workflows
that rebuild the ``docs-builder`` image. Building this image is necessary to
validate changes to the ``Documentation/Dockerfile`` or to the list of Python
dependencies located in ``Documentation/requirements.txt``. The GitHub workflow
uses a pre-built image instead, and won't incorporate changes to these files.

Integration tests also run a full build in the Cilium repository, including the
post-build checks, in particular ``Documentation/Makefile``'s ``check`` target.
Therefore, integration tests are able to raise inconsistencies in
auto-generated files in the documentation.

Ready to merge
--------------

For PRs that only update documentation contents, the CI framework skips tests
that are not relevant to the changes. Therefore, authors or reviewers should
trigger the CI suite by commenting with ``/test``, just like for any other PR.
Once all code owners for the PR have approved, and all tests have passed, the
PR should automatically receive the ``ready-to-merge`` label.
