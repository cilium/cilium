Cilium Release Scripts
======================

# relnotes - Release Notes generation

`GITHUB_TOKEN=xxx relnotes <git revision range>`

The `relnotes` script is derived from Kubernetes and scans for PRs which have
been merged in the specified git revision range and extracts all PRs which have
one of the following labels set:

* release-note/major
* release-note/minor
* release-note/bug

Every PR with one of the above mentioned labels set will be included in the
release notes. The release notes will be sorted according to category defined
by label.

See [Write Release Notes if Needed][1] for details on how to format the body of
a PR to specify the release note text.

## System dependencies

* `lsb_release` tool (Fedora package: `redhat-lsb`)

## Example

1. Generate a GitHub developer access token. (User Profile -> Settings ->
   Developer Settings -> Personal access token -> Generate new token)

   The access token requires access to `public_repo`.

2. Run the script to generate the NEWS.rst file:

   `GITHUB_TOKEN=xxx `./relnotes --markdown-file=NEWS.rst v0.11..v0.12`

   In case the generated `NEWS.rst` file is not as expected, you can run
   `relnotes` with the `--verbose` flag to see individual decision taken for
   each PR.

[1]: https://github.com/kubernetes/community/blob/master/contributors/devel/pull-requests.md#write-release-notes-if-needed
