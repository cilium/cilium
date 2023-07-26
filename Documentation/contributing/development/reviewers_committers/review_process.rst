.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _review_process:

Pull requests review process for committers
===========================================

Review process
--------------

Every committer in the `committers team`_ belongs to `one or more other teams
in the Cilium organization <cilium_teams_>`_ If you would like to be added or
removed from any team, please contact any of the `maintainers`_.

Once a PR is opened by a contributor, GitHub will automatically pick which
`teams <cilium_teams>`_ should review the PR using the ``CODEOWNERS`` file.
Each committer can see the PRs they need to review by filtering by reviews
requested. A good filter is provided in this `link <user_review_filter_>`_ so
make sure to bookmark it.

Reviewers are expected to focus their review on the areas of the code where
GitHub requested their review. For small PRs, it may make sense to simply
review the entire PR. However, if the PR is quite large then it can help to
narrow the area of focus to one particular aspect of the code. When leaving a
review, share which areas you focused on and which areas you think that other
reviewers should look into. This will help others to focus on aspects of review
that have not been covered as deeply.

Belonging to a team does not mean that a committer should know every single
line of code the team is maintaining. For this reason it is recommended that
once you have reviewed a PR, if you feel that another pair of eyes is needed,
you should re-request a review from the appropriate team. In the example below,
the committer belonging to the CI team is re-requesting a review for other team
members to review the PR. This allows other team members belonging to the CI
team to see the PR as part of the PRs that require review in the `filter
<team_review_filter_>`_.

.. image:: ../../../images/re-request-review.png
   :align: center
   :scale: 50%

When all review objectives for all ``CODEOWNERS`` are met, all required CI
tests have passed and a proper release label as been set, you may set the
``ready-to-merge`` label to indicate that all criteria have been met.
Maintainer's little helper might set this label automatically if the previous
requirements were met.

+--------------------------+---------------------------+
| Labels                   | When to set               |
+==========================+===========================+
| ``ready-to-merge``       | PR is ready to be merged  |
+--------------------------+---------------------------+

.. _committers team: https://github.com/orgs/cilium/teams/committers/members
.. _cilium_teams: https://github.com/orgs/cilium/teams/team/teams
.. _maintainers: https://github.com/orgs/cilium/teams/cilium-maintainers/members
.. _user_review_filter: https://github.com/cilium/cilium/pulls?q=is%3Apr+is%3Aopen+draft%3Afalse+user-review-requested%3A%40me+sort%3Aupdated-asc
.. _team_review_filter: https://github.com/cilium/cilium/pulls?q=is%3Apr+is%3Aopen+draft%3Afalse+review-requested%3A%40me+sort%3Aupdated-asc

Code Owners
-----------

.. include:: ../../../codeowners.rst
