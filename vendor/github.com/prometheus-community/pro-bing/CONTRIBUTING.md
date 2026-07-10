# Contributing

First off, thanks for taking the time to contribute!

Remember that this is open source software so please consider the other people who will read your code.
Make it look nice for them, document your logic in comments and add or update the unit test cases.

This library is used by various other projects, companies and individuals in live production environments so please discuss any breaking changes with us before making them.
Feel free to join us in the [#pro-bing](https://gophers.slack.com/archives/C019J5E26U8/p1673599762771949) channel of the [Gophers Slack](https://invite.slack.golangbridge.org/).

## Pull Requests

[Fork the repo on GitHub](https://github.com/prometheus-community/pro-bing/fork) and clone it to your local machine.

```bash
git clone https://github.com/YOUR_USERNAME/pro-bing.git && cd pro-bing
```

Here is a guide on [how to configure a remote repository](https://docs.github.com/en/free-pro-team@latest/github/collaborating-with-issues-and-pull-requests/configuring-a-remote-for-a-fork).

Check out a new branch, make changes, run tests, commit & sign-off, then push branch to your fork.

```bash
$ git checkout -b <BRANCH_NAME>
# edit files
$ make style vet test
$ git add <CHANGED_FILES>
$ git commit -s
$ git push <FORK> <BRANCH_NAME>
```

Open a [new pull request](https://github.com/prometheus-community/pro-bing/compare) in the main `prometheus-community/pro-bing` repository.
Please describe the purpose of your PR and remember link it to any related issues.

*We may ask you to rebase your feature branch or squash the commits in order to keep the history clean.*

## Development Guides

- Run `make style vet test` before committing your changes.
- Document your logic in code comments.
- Add tests for bug fixes and new features.
- Use UNIX-style (LF) line endings.
- End every file with a single blank line.
- Use the UTF-8 character set.
