---
name: Release a new version of Cilium
about: Create a checklist for an upcoming release
title: 'vX.Y.Z release'
labels: kind/release
assignees: ''

---

## Pre-release

- [ ] Check that there are no [release blockers] for the targeted release version
- [ ] Ensure that outstanding [backport PRs] are merged
- [ ] Create a [new project] for the next release version
  - [ ] Move any unresolved issues/PRs into the newly created release project
- [ ] Push a PR including the changes necessary for the new release:
  - [ ] Update the VERSION file to represent X.Y.Z
  - [ ] Update helm charts via `make -C install/kubernetes`
  - [ ] (If applicable) Update the `cilium_version` and `cilium_tag` in
        `examples/getting-started/Vagrantfile`
  - [ ] Update `AUTHORS` via `make update-authors`
  - [ ] Use [Cilium release-notes tool] to generate `CHANGELOG.md`
  - [ ] Point `.github/cilium-actions.yml` to the newly created project
  - [ ] Commit all changes with title `Prepare for release vX.Y.Z`
- [ ] Run CI
- [ ] Merge PR
- [ ] Add build targets for the new release on [Docker Hub]
  - [cilium](https://hub.docker.com/repository/docker/cilium/cilium/builds/edit)
  - [operator](https://hub.docker.com/repository/docker/cilium/operator/builds/edit)
  - [docker-plugin](https://hub.docker.com/repository/docker/cilium/docker-plugin/builds/edit)
- [ ] Create and push *both* tags to GitHub (`vX.Y.Z`, `X.Y.Z`)
- [ ] Wait for docker builds to complete
  - [cilium](https://hub.docker.com/repository/docker/cilium/cilium/builds)
  - [operator](https://hub.docker.com/repository/docker/cilium/operator/builds)
  - [docker-plugin](https://hub.docker.com/repository/docker/cilium/docker-plugin/builds)
- [ ] Create helm charts artifacts in [Cilium charts] repository
- [ ] [Create a release] for the new tag `vX.Y.Z`, using the release notes
      from above
- [ ] Announce the release in #general on Slack (only [@]channel for vX.Y.0)

## Post-release

- [ ] Prepare post-release changes to master branch
  - [ ] Update [Stable releases] section of the README
  - [ ] Update the project pointers in `.github/cilium-actions.yml`
- [ ] Update the `stable` tags for each Cilium image on Docker Hub (if applicable)
- [ ] Update external tools and guides to point to the new Cilium version:
  - [ ] [kops]
  - [ ] [kubespray]


[release blockers]: https://github.com/cilium/cilium/labels/priority%2Frelease-blocker
[backport PRs]: https://github.com/cilium/cilium/pulls?utf8=%E2%9C%93&q=is%3Aopen+is%3Apr+backports
[new project]: https://github.com/cilium/cilium/projects/new
[Cilium release-notes tool]: https://github.com/cilium/release
[Docker Hub]: https://hub.docker.com/orgs/cilium/repositories
[Cilium charts]: https://github.com/cilium/charts
[Create a release]: https://github.com/cilium/cilium/releases/new
[Stable releases]: https://github.com/cilium/cilium#stable-releases
[kops]: https://github.com/kubernetes/kops/
[kubespray]: https://github.com/kubernetes-sigs/kubespray/
