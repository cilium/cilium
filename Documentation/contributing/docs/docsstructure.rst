.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _docs_structure_recommendations:

******************************************
Recommendations on documentation structure
******************************************

This page contains recommendations to help contributors write better
documentation. The goal of better documentation is a better user experience. If
you take only one thing away from this guide, let it be this: don't document
your feature. Instead, **document how your feature guides users on their
journey.**

Maintaining good information architecture
-----------------------------------------

When you add, update, or remove documentation, consider how the change affects
the site's `information architecture`_. Information architecture is what shapes
a user's experience and their ability to accomplish their goals with Cilium. If
an addition, change, or removal would significantly alter a user's journey or
prevent their success, make sure to flag the change clearly in :ref:`upgrade
notes <current_release_required_changes>`.

.. _information architecture: https://www.usability.gov/what-and-why/information-architecture.html

Adding a new page
-----------------

When you need to write completely new content, create one or more new pages as
one of the three following types:

- Concept (no steps, just knowledge)
- Task (how to do one discrete thing)
- Tutorial (how to combine multiple features to accomplish specific goals)

A *concept* explains some aspect of Cilium. Typically, concept pages don't
include sequences of steps. Instead, they link to tasks or tutorials.

For an example of a concept page, see :ref:`Routing <Routing>`.

A *task* shows how to do one discrete thing with Cilium. Task pages give
readers a sequence of steps to perform. A task page can be short or long, but
must remain focused on the task's singular goal. Task pages can blend brief
explanations with the steps to perform, but if you need to provide a lengthy
explanation, write a separate concept and link to it. Link related task and
concept pages to each other.

For an example of a task page, see :ref:`Migrating a Cluster to Cilium
<cni_migration>`.

A *tutorial* shows how to accomplish a goal using multiple Cilium features.
Tutorials are flexible: for example, a tutorial page could provide several
discrete sequences of steps to perform, or show how related pieces of code
could interact. Tutorials can blend brief explanations with the steps to
perform, but lengthy explanations should link to related concept topics.

For an example of a tutorial page, see :ref:`Inspecting Network Flows with the
CLI <hubble_cli>`.

.. note::

  You may need to add multiple pages to support a new feature. For example, if
  a new feature requires an explanation of its underlying ideas, add a concept
  page as well as a task page.

Updating an existing page
-------------------------

Consider whether you can update an existing page or whether to add a new one.

If adding or updating content to a page keeps it centered on a single concept
or task, then you can update an existing page. If adding or updating content to
a page expands it to include multiple concepts or tasks, then add new pages for
individual concepts and tasks.

If you're moving a page and changing its URL, make sure you update every link
to that page in the documentation. Ask on `Cilium Slack`_ (``#sig-docs``) for
someone to set up a HTTP redirection from the old URL to the new one, if
necessary.

Removing content and entire pages
---------------------------------

Removing stale content is a part of maintaining healthy docs.

Whether you're removing stale content on a page or removing a page altogether,
make sure to consider the impact of removal on a user's journey. Specific
considerations include:

- Updating any links to removed content
- Ensuring users have clear guidance on what to do next

.. note::

  Without a clearly defined user journey, evaluation is largely qualitative.
  Practice empathy: would someone succeed if they had your skills but not your
  context?
