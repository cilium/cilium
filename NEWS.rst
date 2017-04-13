****
NEWS
****

0.8.2
=====

- Separate state directory inside runtime directory (`GH #537 <https://github.com/cilium/cilium/pull/537>`_)
- Fix all remaining testsuites and have Jenkins fail properly on all failures (`GH #513 <https://github.com/cilium/cilium/pull/513>`_)
- policy: Support carrying part of the path in the name (`GH #533 <https://github.com/cilium/cilium/pull/533>`_)
- Temporary fix: Set net.ipv6.conf.all.disable_ipv6=1 as Docker disables it by mistake (`GH #544 <https://github.com/cilium/cilium/pull/544>`_, `libnetwork #1720 <https://github.com/docker/libnetwork/issues/1720>`_)

0.8.1
=====

- Fixed a bug when policy was not imported correctly (`GH #507 <https://github.com/cilium/cilium/pull/507>`_)
- Improved logging readability (`GH #499 <https://github.com/cilium/cilium/pull/499>`_)
- Give L7 policy fields better names (`GH #500 <https://github.com/cilium/cilium/pull/500>`_)

0.8.0
=====

- First initial release
