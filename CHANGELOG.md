# Changelog

# v1.6.6

Summary of Changes
------------------

**Minor Changes:**
* golang: update to 1.12.15 (#9874, @aanm)
* golang: update to 1.12.16 (#9987, @aanm)

**Bugfixes:**
* Fix to allocate a global identity for an empty container label-set. (Backport PR #9827, Upstream PR #9821, @borkmann)
* Enable IP forwarding on daemon start (Backport PR #9841, Upstream PR #8954, @mrostecki)
* eni: Fix releases of excess IPs (Backport PR #9962, Upstream PR #9858, @tgraf)
* cni: Fix IP leak when CNI ADD times out (Backport PR #9962, Upstream PR #9913, @tgraf)
* cni: Fix noisy warning "Unknown CNI chaining configuration" (Backport PR #9962, Upstream PR #9937, @tgraf)
* Fix cilium installation in GCloud beta "rapid" channel (Backport PR #10007, Upstream PR #9959, @joestringer)
* garbage collect stale distributed locks (Backport PR #10007, Upstream PR #9982, @aanm)
* fqdn: Support setting tofqdns-min-ttl to 0 (Backport PR #9753, Upstream PR #9743, @raybejjani)

**Misc Changes:**
* Add missing words to spelling_wordlist (Backport PR #9753, Upstream PR #9643, @ungureanuvladvictor)
* Fix GC Locks bugs (Backport PR #10007, Upstream PR #10005, @aanm)
* nodeinit/templates: fix indentation of sys-fs-bpf (Backport PR #10024, Upstream PR #10008, @aanm)
* v1.6: install: Update the chart versions (#9788, @joestringer)

**Other Changes:**
* update k8s tested versions to v1.14.10, v1.15.7 and v1.16.4 (#9870, @aanm)
* .github: Update actions to v1.6.6 project (#9775, @joestringer)
* Fix github actions 1.6 (#9781, @aanm)
