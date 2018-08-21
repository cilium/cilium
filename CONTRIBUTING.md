# How to Contribute

This is the short version of the instructions on how to contribute to Cilium,
for more details, see the [Developer / Contributor Guide](http://docs.cilium.io/en/doc-1.0/contributing/).

## Getting Started

* Make sure you have a [GitHub account](https://github.com/signup/free).
* Set up your own [Golang development environment](https://golang.org/doc/code.html)
* Clone the cilium repository
  * `go get -d github.com/cilium/cilium`
  * `cd $GOPATH/src/github.com/cilium/cilium`
* Bring up the vagrant box which will provide all dependencies for development.
  * `./contrib/vagrant/start.sh`
  * `vagrant ssh`

## Making Changes

* Create a topic branch: `git checkout -b myBranch master`
* Make the changes you want
* Separate the changes into logical commits. See [commit message
  conventions](#commit-message-conventions) below for an example.
  * Describe the changes in the commit messages. Focus on answering the
    question why the change is required and document anything that might be
    unexpected.
  * If any description is required to understand your code changes, then those
    instructions should be code comments instead of statements in the commit
    description.
* Make sure your changes meet the following criteria:
  * New code is covered by go unit tests
  * End to end integration / runtime tests have been extended or added. If not
    required, mention in the commit message what existing test covers the new
    code.
  * Follow-up commits are squashed together nicely. Commits should separate
    logical chunks of code and not represent a chronological list of changes.
* Run `git diff --check` to catch obvious whitespace violations
* Run `make` to build your changes. This will also run `go fmt` and error out
  on any golang formatting errors.
* Run `make tests` to run the go unit tests
* Run `make runtime-tests` to run the runtime tests

## Submitting Changes

* Fork the Cilium repository to your own personal GitHub space or request
  access to a Cilium developer account on Slack
* Push your changes to the topic branch in your fork of the repository.
* Submit a pull request on https://github.com/cilium/cilium
  * Provide a high level description of the PR, feel free to refer to
    individual commit messages for details. Remember that the commit
    descriptions will be used for the git revision history, not the PR
    description text.
* As you submit the pull request, your PR will automatically be passed through
  the CI pipeline which will run the following tests:
  * Hound: basic `golang/lint` static code analyzer. You need to make the puppy
    happy.
  * Jenkins: Will run a series of tests:
    * Unit tests
    * Single node runtime tests
    * Multi node Kubernetes tests
* As part of the submission, GitHub will have requested a review from the
  respective code owners according to the `CODEOWNERS` file in the repository.
  * Address any feedback received from the reviewers
  * You can push individual commits to address feedback and then rebase your
    branch at the end before merging.
* Owners of the repository will automatically adjust the labels on the pull
  request to track its state and progress towards merging. See [Use of GitHub
  Labels](#use-of-github-labels) for more information.
* Once the PR has been reviewed and the CI tests have passed, the PR will be
  merged by one of the repository owners. In case this does not happen, ping us
  on Slack.

### Release Note specification

If your change should be mentioned in the release notes, then assign one of
the following labels to your PR or ask a project owner to do it for you:

* `release-note/major`: Major feature change
* `release-note/minor`: Minor feature change
* `release-note/bug`: Bugfix

The text for the release note entry can be specified as a code block using
the `release-note` type:

    ```release-note
    This is a release note text
    ```

If multiple lines are provided, then the first line serves as the high level
bullet point item and any additional line will be added as a sub item to the
first line.

## Commit message conventions

    subsystem: Summary of my change no longer than 80 characters

    Summary text describing the motivation of the change. Should address the
    following questions:
     - Why is the change required?
     - What decision were made and why?

    Fixes: #2222

    Signed-off-by: Jeanette Developer <jeanette.developer@corp.io>

## Issue tracker

All ongoing and future work as well as all bugs reports are managed via GitHub
issues [GitHub issues](https://github.com/cilium/cilium/issues).

If you are a user and are looking to report a bug or request a feature, then
please refer to the [Issue template] directly.

## Use of GitHub Labels

* `area/*`: Describes the area of code that the issue/pull request affect. If
  multiple areas area affected, all corresponding labels should be added.
* `dont-merge/*`: A required condition for merging is unmet that requires
  attention by the original pull request author.
  * `dont-merge/needs-release-note`: The PR is significant and requires a
    release note to be added to the body of the pull request.
  * `dont-merge/needs-sign-off`: The commits in the pull request need to be
    signed off, please see [Developer’s Certificate of Origin]
* `good first issue`: This is a great issue to get started contributing to
  Cilium.
* `help wanted`: Looking for help to finish this pull request. This can refer
  to feedback or help in form of contributions.
* `kind/*`: Describes the kind of bug/pull request.
  * `kind/bug`: This is a bug report or a pull request fixing a bug
  * `kind/enhancement`: This is request for an enhacements or a pull request
    implementing a feature.
  * `kind/question`: This was a bug report or question that was resolved and
    now is now part of the FAQ.
* `need more info`: Additional information is required from the reporter before
  progress can be made.
* `needs/triage`: This is a bug report that has not been looked at yet.
  Requires to be triaged.
* `pending review`: The pull request is seeking for reviews by the code owners.
* `priority/{high|medium|low}`: Current assessment of priority of this feature
  or bug.
* `project/*`: Special projects or initiatives that will affect many issues and
  pull requests.
  * `project/1.0-gap`: This issue has been identified as a gap to reach 1.0.
* `release-note/{major|minor|bug}`: Include this pull request in the release
  notes of the next release.
* `requires doc change`: This pull request requires doc changes
* `stable/backport`: This is a backport to the stable branch
* `stable/needs-backport`: This pull request must be backported to stable
* `stable/backport-done`: Backport has been done.
* `wip`: Work in progress, do not review yet.

[Developer’s Certificate of Origin]: http://docs.cilium.io/en/doc-1.0/contributing/#developer-s-certificate-of-origin
[Issue template]: https://raw.githubusercontent.com/cilium/cilium/master/.github/issue_template.md
