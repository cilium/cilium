.. _glossary:

Glossary
========

Cilium has some terms with special meanings. These should all be covered
throughout the documentation but for convenience we have also listed some of
them below with short descriptions. If you need more information, please ask us
on `Slack <https://cilium.herokuapp.com>`_. Feel free to extend this document
with words you expected to see here.

Endpoint
  A Cilium endpoint is one or more application containers which can be
  addressed by an individual IP address.
Identity
  The identity of an endpoint is derived based on the labels associated with the
  pod or container.
Label
  Cilium labels are similar to regular container names / labels, the exception
  being that they can be key / value pairs.
Policy
  A Cilium policy consists of a list of rules. The security policy can be
  specified in The Kubernetes NetworkPolicy format or The Cilium policy
  language.
