# Changelog

## v1.11.0-rc2

Summary of Changes
------------------

**Major Changes:**
* Support policy matching against kube-apiserver (#17823, @joestringer)

**Minor Changes:**
* docs: Remove firewall hack for OKD GSG (#17924, @errordeveloper)
* helm: Disable BPF masquerading in v1.10+ (#17824, @pchaigno)

**Bugfixes:**
* bugtool: fix data race occurring when running commands (#17916, @rolinh)
* Fixes for IPsec and endpoint routes (#17865, @kkourt)

**CI Changes:**
* ci: update CI Vagrant VM IP addresses (#17733, @nbusseneau)
* ci: update CI Vagrant VM IP addresses (#17900, @nbusseneau)
* Revert "ci: update CI Vagrant VM IP addresses" (#17898, @ti-mo)
* tests: Disable K8s upstream tests that we do not support (#17828, @nathanjsweet)
* workflows: disable `no-policies/pod-to-service` in clustermesh (#17894, @nbusseneau)

**Misc Changes:**
* .github: add bug_report form to submit Cilium bugs (#17933, @aanm)
* build(deps): bump 8398a7/action-slack from 3.10.0 to 3.11.0 (#17886, @dependabot[bot])
* build(deps): bump azure/CLI from 1.0.5 to 1.0.6 (#17885, @dependabot[bot])
* build(deps): bump azure/login from 1.4.0 to 1.4.1 (#17884, @dependabot[bot])
* build(deps): bump github.com/aliyun/alibaba-cloud-sdk-go from 1.61.1325 to 1.61.1327 (#17891, @dependabot[bot])
* build(deps): bump github.com/aliyun/alibaba-cloud-sdk-go from 1.61.1327 to 1.61.1331 (#17901, @dependabot[bot])
* build(deps): bump github/codeql-action from 1.0.22 to 1.0.23 (#17920, @dependabot[bot])
* neigh: Clean up stale/untracked non-GC'ed neighbors (#17918, @borkmann)
* neigh: Init new neighbor for older kernel with NUD_STALE (#17932, @borkmann)
* Prepare for release v1.11.0-rc1 (#17876, @aanm)
