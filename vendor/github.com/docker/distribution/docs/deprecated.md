<!--[metadata]>
+++
title = "Deprecated Features"
description = "describes deprecated functionality"
keywords = ["registry, manifest, images, signatures, repository, distribution, digest"]
[menu.main]
parent="smn_registry_ref"
weight=8
+++
<![end-metadata]-->

# Docker Registry Deprecation

This document details functionality or components which are deprecated within
the registry.

### v2.5.0

The signature store has been removed from the registry.  Since `v2.4.0` it has
been possible to configure the registry to generate manifest signatures rather
than load them from storage.   In this version of the registry this becomes
the default behavior.  Signatures which are attached to manifests on put are
not stored in the registry.  This does not alter the functional behavior of
the registry.

Old signatures blobs can be removed from the registry storage by running the
garbage-collect subcommand.
