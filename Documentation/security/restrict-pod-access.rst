.. only:: not (epub or latex or html)

    WARNING: You are looking at unreleased Cilium documentation.
    Please use the official rendered version released here:
    https://docs.cilium.io

.. _security_restrict_pod_access:

========================================
Restricting privileged Cilium pod access
========================================

This page shows you how to restrict privileged access to Cilium pods by limiting access from the Kubernetes API, specifically from `kubernetes exec pod`_.

.. include:: gsg_requirements.rst

Background
----------

The Cilium agent needs some specific Linux capabilities to perform essential system and network operations.

Cilium relies on Kubernetes and containers to set up the environment and mount the corresponding volumes. Cilium doesn't perform any extra operations that could result in an unsafe volume mount. 

Cilium needs kernel interfaces to properly configure the environment. Some kernel interfaces are part of the ``/proc`` filesystem, which includes host and machine configurations that can't be virtualized or namespaced.

If ``pod exec`` operations aren't restricted, then remote `exec into pods`_ and containers defeats Linux namespace restrictions.

The Linux kernel restricts joining other namespaces by default. To enter the Cilium container, the ``CAP_SYS_ADMIN`` capability is required in both the current user namespace and in the Cilium user namespace (the initial namespace). If both namespaces have the ``CAP_SYS_ADMIN`` capability, then this is already a privileged access.

To prevent privileged access to Cilium pods, restrict access to the Kubernetes API and arbitrary ``pod exec`` operations.

Restrict authorization for ``kubernetes exec pod``
--------------------------------------------------

To restrict access to Cilium pods through ``kubernetes exec pod``:

1. Configure `RBAC authorization`_ in Kubernetes.

2. Limit `access to the proxy subresource of Nodes`_.

References
----------

For more information about namespace security, visit:

- https://man7.org/linux/man-pages/man7/user_namespaces.7.html
- https://man7.org/linux/man-pages/man1/nsenter.1.html
- https://man7.org/linux/man-pages/man2/setns.2.html

.. _kubernetes exec pod: https://kubernetes.io/docs/tasks/debug/debug-application/get-shell-running-container/
.. _exec into pods: https://kubernetes.io/docs/tasks/debug/debug-application/get-shell-running-container/
.. _RBAC authorization: https://kubernetes.io/docs/reference/access-authn-authz/rbac/
.. _access to the proxy subresource of Nodes: https://kubernetes.io/docs/concepts/security/rbac-good-practices/#access-to-proxy-subresource-of-nodes