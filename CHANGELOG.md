# Changelog

# v1.5.13

Summary of Changes
------------------

**Bugfixes:**
* cilium: only enable IPv6 forwarding if IPv6 is enabled (Backport PR #10136, Upstream PR #9034, @jrfastab)
* Envoy fixes for CVE-2020-8659, CVE-2020-8660, CVE-2020-8661, CVE-2020-8664 (Backport PR #10445, Upstream PR #10434, @jrajahalme)
* ipam: Protect release from releasing alive IP (Backport PR #10136, Upstream PR #10066, @tgraf)
* pkg/bpf: Protect attr in perf_linux.go with runtime.KeepAlive (#10205, @brb)
* pkg/bpf: Protect each uintptr with runtime.KeepAlive (Backport PR #10253, Upstream PR #10168, @brb)

**CI Changes:**
* test: Wait for Istio POD termination before deleting istio-system or cilium (Backport PR #10445, Upstream PR #10325, @jrajahalme)

**Misc Changes:**
* bpf: Fix space hack in Makefile (Backport PR #10253, Upstream PR #10173, @brb)
* doc: Fix links to contributing guide (Backport PR #10445, Upstream PR #10322, @CybrPunk)
* Documentation: Lock dependency to fix build (Backport PR #10439, Upstream PR #10419, @Ropes)
* golang: update to 1.12.17 (#10209, @aanm)
* Update release process steps (Backport PR #10136, Upstream PR #10035, @aanm)
* Use -F flag in git log in check-stable script (Backport PR #10445, Upstream PR #10283, @nebril)

**Other Changes:**
* .github: update github-actions project (#10046, @aanm)

# v1.5.12

Summary of Changes
------------------

**Minor Changes:**
* golang: update to 1.12.15 (#9873, @aanm)
* golang: update to 1.12.16 (#9986, @aanm)

**Bugfixes:**
* Fix to allocate a global identity for an empty container label-set. (Backport PR #9829, Upstream PR #9821, @borkmann)
* Enable IP forwarding on daemon start (Backport PR #9839, Upstream PR #8954, @mrostecki)
* cni: Fix IP leak when CNI ADD times out (Backport PR #10004, Upstream PR #9913, @tgraf)
* garbage collect stale distributed locks (Backport PR #10004, Upstream PR #9982, @aanm)

**Misc Changes:**
* Fix GC Locks bugs (Backport PR #10004, Upstream PR #10005, @aanm)

**Other Changes:**
* Fix github actions 1.5 (#9782, @aanm)
