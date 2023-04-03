.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

..       This has been bluntly copied from the excellent committer guidelines
         written for the Open vSwitch project and has then been adapted. It is
         based on the following files:
         https://github.com/openvswitch/ovs/blob/master/Documentation/internals/committer-grant-revocation.rst
         https://github.com/openvswitch/ovs/blob/master/Documentation/internals/committer-responsibilities.rst

..       Additional ideas have been borrowed from https://github.com/envoyproxy/envoy/blob/main/GOVERNANCE.md

..       Licensed under the Apache License, Version 2.0 (the "License"); you may
         not use this file except in compliance with the License. You may obtain
         a copy of the License at

             http://www.apache.org/licenses/LICENSE-2.0

 ..      Unless required by applicable law or agreed to in writing, software
         distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
         WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
         License for the specific language governing permissions and limitations
         under the License.

Cilium Committer Grant/Revocation Policy
========================================

A Cilium committer is a participant in the project with the ability to
commit code directly to the main branch. Commit access grants a
broad ability to affect the progress of the project as presented by its
most important artifact, the code and related resources that produce
working binaries of Cilium. As such it represents a significant level of
trust in an individual's commitment to working with other committers and
the community at large for the benefit of the project. It can not be
granted lightly and, in the worst case, must be revocable if the trust
placed in an individual was inappropriate.

Becoming a Cilium committer also grants the status of Cilium `"maintainer" in
CNCF parlance
<https://contribute.cncf.io/about/maintainers-circle/#who-is-a-maintainer>`__. 
This means that Cilium committers can use the `CNCF Service
Desk <https://github.com/cncf/servicedesk>`__ to request services on behalf of the
project, and will also receive a vote on certain CNCF matters. 

This document suggests guidelines for granting and revoking commit
access. It is intended to provide a framework for evaluation of such
decisions without specifying deterministic rules that wouldn't be
sensitive to the nuance of specific situations. In the end the decision
to grant or revoke committer privileges is a judgment call made by the
existing set of committers.

For the list of current committers, see MAINTAINERS.md_.

.. _MAINTAINERS.md: https://raw.githubusercontent.com/cilium/cilium/main/MAINTAINERS.md

Expectations for Developers with commit access
----------------------------------------------

Pre-requisites
~~~~~~~~~~~~~~

Be familiar with the :ref:`dev_guide` and have `2-Factor Authentication
<https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa/configuring-two-factor-authentication>`__ 
enabled on your Github account.

Review
~~~~~~

Code (yours or others') must be reviewed publicly (by you or others)
before you push it to the repository. Every change needs at least one review.

If one or more people know an area of code particularly well, code that
affects that area should ordinarily get a review from one of them.

The riskier, more subtle, or more complicated the change, the more
careful the review required. When a change needs careful review, use
good judgment regarding the quality of reviews. If a change adds 1000
lines of new code, and a review posted 5 minutes later says just "Looks
good," then this is probably not a quality review.

(The size of a change is correlated with the amount of care needed in
review, but it is not strictly tied to it. A search and replace across
many files may not need much review, but one-line optimization changes
can have widespread implications.)

Regularly review submitted code in areas where you have expertise.
Consider reviewing other code as well.

Git conventions
~~~~~~~~~~~~~~~

If you apply a change (yours or another's) then it is your
responsibility to handle any resulting problems, especially broken
builds and other regressions. If it is someone else's change, then you
can ask the original submitter to address it. Regardless, you need to
ensure that the problem is fixed in a timely way. The definition of
"timely" depends on the severity of the problem.

If a bug is present on main and other branches, fix it on main first,
then backport the fix to other branches. Straightforward backports
do not require additional review (beyond that for the fix on main).

Feature development should be done only on main. Occasionally it makes
sense to add a feature to the most recent release branch, before the
first actual release of that branch. These should be handled in the same
way as bug fixes, that is, first implemented on main and then
backported.

Keep the authorship of a commit clear by maintaining a correct list of
"Signed-off-by:"s. If a confusing situation comes up, as it occasionally
does, bring it up in the development forums. If you explain the use of
"Signed-off-by:" to a new developer, explain not just how but why, since
the intended meaning of "Signed-off-by:" is more important than the
syntax.

Use Reported-by: and Tested-by: tags in commit messages to indicate the
source of a bug report.

Keep the `AUTHORS <https://github.com/cilium/cilium/blob/main/AUTHORS>`__ file up to date.

CNCF Resources
~~~~~~~~~~~~~~

Any Maintainer may suggest a request for `CNCF Resources <https://www.cncf.io/services-for-projects/>`__
through the `CNCF Service Desk <https://cncfservicedesk.atlassian.net/servicedesk/customer/portal/1>`__.
The Maintainers may also choose to delegate working with the CNCF to non-Maintainer community members.

Code of Conduct
~~~~~~~~~~~~~~~

`Code of Conduct <https://github.com/cilium/cilium/blob/main/CODE_OF_CONDUCT.md>`__
violations by community members will be discussed and resolved on the private
committers Slack channel. If the reported Code of Conduct violator is a Maintainer, the 
Maintainers will instead designate two Maintainers to work with the
`CNCF CoC Committee <https://www.cncf.io/conduct/procedures/>`__.  

Granting Commit Access
----------------------

Granting commit access should be considered when a candidate has
demonstrated the following in their interaction with the project:

-  Contribution of significant new features through the patch submission
   process where:

-  Submissions are free of obvious critical defects
-  Submissions do not typically require many iterations of improvement
   to be accepted

-  Consistent participation in code review of other's patches, including
   existing committers, with comments consistent with the overall
   project standards

-  Assistance to those in the community who are less knowledgeable
   through active participation in project forums.

-  Plans for sustained contribution to the project compatible with the
   project's direction as viewed by current committers.

-  Commitment to meet the expectations described in the "Expectations of
   Developer's with commit access"

The process to grant commit access to a candidate is simple:

-  An existing committer nominates the candidate by sending a message in the
   #committers Slack channel to all existing committers with information
   substantiating the contributions of the candidate in the areas described
   above.

-  All existing committers discuss the pros and cons of granting commit
   access to the candidate in the Slack thread.

-  When the discussion has converged or a reasonable time has elapsed
   without discussion developing (e.g. a few business days) the
   nominator calls for a final decision on the candidate with a followup
   Slack poll.

-  Each committer may vote yes, no, or abstain by responding to the Slack poll.
   A failure to reply is an implicit abstention.

-  After votes from all existing committers have been collected or a
   reasonable time has elapsed for them to be provided (e.g. a couple of
   business days) the votes are evaluated. To be granted commit access
   the candidate must receive yes votes from a majority of the existing
   committers and zero no votes. Since a no vote is effectively a veto
   of the candidate it should be accompanied by a reason for the vote.

-  The nominator summarizes the result of the vote in a Slack message to all
   existing committers. Report the votes after applying the :ref:`vote_limit`.

-  If the vote to grant commit access passed, the candidate is contacted
   with an invitation to become a committer to the project which asks
   them to agree to the committer expectations documented on the project
   web site.

-  If the candidate agrees, access is granted by setting up commit access.

    #. Delete the nomination poll and related discussions to preserve the
       privacy of any discussions regarding the newly nominated committer.
       If any discussion may be relevant for subsequent project governance
       discussion, those remarks may optionally be summarized and re-posted
       to the channel. The final vote summary does not need to be deleted.

    #. Invite the new committer to the #committers Slack channel.

    #. Add the new committer to the list in MAINTAINERS.md_.

    #. Add the new committer to the `CNCF's list of Cilium maintainers
       <https://github.com/cncf/foundation/blob/main/README.md#other-content>`__.

    #. Add the new committer to the `Committers team
       <https://github.com/orgs/cilium/teams/committers>`__.

Revoking Commit Access
----------------------

There are two situations in which commit access might be revoked.

The straightforward situation is a committer who is no longer active in
the project and has no plans to become active in the near future. The
process in this case is:

-  Any time after a committer has been inactive for more than 6 months
   any other committer to the project may identify that committer as a
   candidate for revocation of commit access due to inactivity.

-  The plans of revocation should be sent in a private Slack message or email
   to the candidate.

-  If the candidate for removal states plans to continue participating
   no action is taken and this process terminates.

-  If the candidate replies they no longer require commit access then
   commit access is removed and a notification is sent to the candidate
   and all existing committers.

-  If the candidate can not be reached within 1 week of the first
   attempting to contact this process continues.

-  A message proposing removal of commit access is sent to the candidate
   and all other committers.

-  If the candidate for removal states plans to continue participating
   no action is taken.

-  If the candidate replies they no longer require commit access then
   their access is removed.

-  If the candidate can not be reached within 2 months of the second
   attempting to contact them, access is removed.

-  In any case, where access is removed, this fact is published through
   a Slack message to all existing committers (including the candidate for
   removal). The candidate is also removed from the CNCF's list of Cilium
   maintainers as documented `here
   <https://github.com/cncf/foundation/blob/main/README.md#other-content>`__. 

The more difficult situation is a committer who is behaving in a manner
that is viewed as detrimental to the future of the project by other
committers. This is a delicate situation with the potential for the
creation of division within the greater community and should be handled
with care. The process in this case is:

-  Discuss the behavior of concern with the individual privately and
   explain why you believe it is detrimental to the project. Stick to
   the facts and keep the Slack messages professional. Avoid personal
   attacks and the temptation to hypothesize about unknowable information
   such as the other's motivations. Make it clear that you would prefer
   not to discuss the behavior more widely but will have to raise it with
   other contributors if it does not change. Ideally the behavior is
   eliminated and no further action is required. If not,

-  Start a Slack thread with all committers, including the source of
   the behavior, describing the behavior and the reason it is
   detrimental to the project. The message should have the same tone as
   the private discussion and should generally repeat the same points
   covered in that discussion. The person whose behavior is being
   questioned should not be surprised by anything presented in this
   discussion. Ideally the wider discussion provides more perspective to
   all participants and the issue is resolved. If not,

-  Start a Slack thread with all committers except the source of the
   detrimental behavior requesting a vote on revocation of commit
   rights. Cite the discussion among all committers and describe all the
   reasons why it was not resolved satisfactorily. The Slack message
   should be carefully written with the knowledge that the reasoning it
   contains may be published to the larger community to justify the
   decision.

-  Each committer may vote yes, no, or abstain by responding to the
   Slack poll. A failure to reply is an implicit abstention.

-  After all votes have been collected or a reasonable time has elapsed
   for them to be provided (e.g. a couple of business days) the votes
   are evaluated. For the request to revoke commit access for the
   candidate to pass it must receive yes votes from two thirds of the
   existing committers.

-  anyone that votes no must provide their reasoning, and

-  if the proposal passes then counter-arguments for the reasoning in no
   votes should also be documented along with the initial reasons the
   revocation was proposed. Ideally there should be no new
   counter-arguments supplied in a no vote as all concerns should have
   surfaced in the discussion before the vote.

-  The original person to propose revocation summarizes the result of
   the vote in a Slack message to all existing committers excepting the
   candidate for removal.

-  If the vote to revoke commit access passes, access is removed and the
   candidate for revocation is informed of that fact and the reasons for
   it as documented in the Slack message requesting the revocation vote.

-  Ideally the revoked committer peacefully leaves the community and no
   further action is required. However, there is a distinct possibility
   that they will try to generate support for their point of view
   within the larger community. In this case the reasoning for removing
   commit access as described in the request for a vote will be
   published to the community.

Changing the Policy
-------------------

The process for changing the policy is:

-  Propose the changes to the policy in a Slack message to all current
   committers and request discussion.

-  After an appropriate period of discussion (a few days) update the
   proposal based on feedback if required and resend it to all current
   committers with a request for a formal vote.

-  After all votes have been collected or a reasonable time has elapsed
   for them to be provided (e.g. a couple of business days) the votes
   are evaluated. For the request to modify the policy to pass it must
   receive yes votes from two thirds of the existing committers.


Voting
======

In general, we prefer that technical issues and maintainer membership are
amicably worked out between the persons involved. If a dispute cannot be
decided independently, the committers and maintainers can be called in to
decide an issue. If the maintainers themselves cannot decide an issue, the
issue will be resolved by voting. The voting process is a simple majority in
which each committer and each maintainer receives one vote.

Votes are done in the Slack channel #committers using Slack polls. A failure to
vote is an implicit abstention.

.. _vote_limit:

Company Block Vote Limit
------------------------

In the spirit of ensuring a diverse community, the number of votes a single
company can receive is limited to 6 votes. The company affiliation of
maintainers and committers is documented in the MAINTAINERS.md_ file.

Votes are counted within the company association and then broken down
proportionally. Example: 7 committers from a company vote, 6 votes yes,
1 vote no.

 * 6 / (7/6) = 5.14 = 5 votes yes
 * 1 / (7/6) = 0.85 = 1 vote no

Templates
=========

Nomination to Grant Commit Access
---------------------------------

::

    I would like to nominate *[candidate]* for commit access. I believe
    *[he/she/they]* has met the conditions for commit access described in the
    committer grant policy on the project web site in the following ways:

    *[list of requirements & evidence]*

    Please reply to all in this message thread with your comments and
    questions. If that discussion concludes favorably I will request a formal
    vote on the nomination in a few days.

Vote to Grant Commit Access
---------------------------

::

    I nominated *[candidate]* for commit access on *[date]*. Having allowed
    sufficient time for discussion it's now time to formally vote on the
    proposal.

    Please reply to all in this thread with your vote of: YES, NO, or ABSTAIN.
    A failure to reply will be counted as an abstention. If you vote NO, by our
    policy you must include the reasons for that vote in your reply. The
    deadline for votes is *[date and time]*.

    If a majority of committers vote YES and there are zero NO votes commit
    access will be granted.

Vote Results for Grant of Commit Access
---------------------------------------

Vote results should be reported based on the vote count, i.e. after applying
the :ref:`vote_limit`.

::

    The voting period for granting to commit access to *[candidate]* initiated
    at *[date and time]* is now closed with the following results:

    YES: *[count of yes votes]* (*[% of voters]*)

    NO: *[count of no votes]* (*[% of voters]*)

    ABSTAIN: *[count of abstentions]* (*[% of voters]*)

    Based on these results committer status *[is/is NOT]* granted and *[she/he/they]* 
    *[will/will NOT]* be added to the list of Cilium maintainers at the CNCF.

Invitation to Accepted Committer
--------------------------------

::

    Due to your sustained contributions to the Cilium project we
    would like to provide you with commit access to the project repository.
    Developers with commit access must agree to fulfill specific
    responsibilities described in the source repository:

        /Documentation/commit-access.rst

    Please let us know if you would like to accept commit access and if so that
    you agree to fulfill these responsibilities. Once we receive your response
    we'll set up access. We're looking forward continuing to work together to
    advance the Cilium project.

Proposal to Remove Commit Access for Inactivity
-----------------------------------------------

::

    Committer *[candidate]* has been inactive for *[duration]*. I have
    attempted to privately contacted *[him/her]* and *[he/she/they]* could not be
    reached.

    Based on this I would like to formally propose removal of commit access.
    If a response to this message documenting the reasons to retain commit
    access is not received by *[date]* access will be removed.

Notification of Commit Removal for Inactivity
---------------------------------------------

::

    Committer *[candidate]* has been inactive for *[duration]*. *[He/she/they]*
    *[stated no commit access is required/failed to respond]* to the formal
    proposal to remove access on *[date]*. Commit access has now been removed 
    and *[she/he/they]* is being removed from the CNCF's list of Cilium maintainers.

Proposal to Revoke Commit Access for Detrimental Behavior
---------------------------------------------------------

::

    I regret that I feel compelled to propose revocation of commit access for
    *[candidate]*. I have privately discussed with *[him/her/them]* the following
    reasons I believe *[his/her/their]* actions are detrimental to the project and we
    have failed to come to a mutual understanding:

    *[List of reasons and supporting evidence]*

    Please reply to all in this thread with your thoughts on this proposal.  I
    plan to formally propose a vote on the proposal on or after *[date and
    time]*.

    It is important to get all discussion points both for and against the
    proposal on the table during the discussion period prior to the vote.
    Please make it a high priority to respond to this proposal with your
    thoughts.

Vote to Revoke Commit Access
----------------------------

::

    I nominated *[candidate]* for revocation of commit access on *[date]*.
    Having allowed sufficient time for discussion it's now time to formally
    vote on the proposal.

    Please reply to all in this thread with your vote of: YES, NO, or ABSTAIN.
    A failure to reply will be counted as an abstention. If you vote NO, by our
    policy you must include the reasons for that vote in your reply. The
    deadline for votes is *[date and time]*.

    If 2/3rds of committers vote YES commit access will be revoked.

    The following reasons for revocation have been given in the original
    proposal or during discussion:

    *[list of reasons to remove access]*

    The following reasons for retaining access were discussed:

    *[list of reasons to retain access]*

    The counter-argument for each reason for retaining access is:

    *[list of counter-arguments for retaining access]*

Vote Results for Revocation of Commit Access
--------------------------------------------

Vote results should be reported based on the vote count, i.e. after applying
the :ref:`vote_limit`.

::

    The voting period for revoking the commit access of *[candidate]* initiated
    at *[date and time]* is now closed with the following results:

    -  YES: *[count of yes votes]* (*[% of voters]*)

    -  NO: *[count of no votes]* (*[% of voters]*)

    -  ABSTAIN: *[count of abstentions]* (*[% of voters]*)

    Based on these results commit access *[is/is NOT]* revoked. The following
    reasons for retaining commit access were proposed in NO votes:

    *[list of reasons]*

    The counter-arguments for each of these reasons are:

    *[list of counter-arguments]*

Notification of Commit Revocation for Detrimental Behavior
----------------------------------------------------------

::

    After private discussion with you and careful consideration of the
    situation, the other committers to the Cilium project have
    concluded that it is in the best interest of the project that your commit
    access to the project repositories be revoked and this has now occurred. 
    Your address is also being removed from the CNCF's list of Cilium maintainers.

    The reasons for this decision are:

    *[list of reasons for removing access]*

    While your goals and those of the project no longer appear to be aligned we
    greatly appreciate all the work you have done for the project and wish you
    continued success in your future work.
