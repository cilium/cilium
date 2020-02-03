# Changelog

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
