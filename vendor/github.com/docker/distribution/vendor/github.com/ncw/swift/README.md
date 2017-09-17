Swift
=====

This package provides an easy to use library for interfacing with
Swift / Openstack Object Storage / Rackspace cloud files from the Go
Language

See here for package docs

  http://godoc.org/github.com/ncw/swift

[![Build Status](https://api.travis-ci.org/ncw/swift.svg?branch=master)](https://travis-ci.org/ncw/swift) [![GoDoc](https://godoc.org/github.com/ncw/swift?status.svg)](https://godoc.org/github.com/ncw/swift) 

Install
-------

Use go to install the library

    go get github.com/ncw/swift

Usage
-----

See here for full package docs

- http://godoc.org/github.com/ncw/swift

Here is a short example from the docs

    import "github.com/ncw/swift"

    // Create a connection
    c := swift.Connection{
        UserName: "user",
        ApiKey:   "key",
        AuthUrl:  "auth_url",
        Domain:   "domain",  // Name of the domain (v3 auth only)
        Tenant:   "tenant",  // Name of the tenant (v2 auth only)
    }
    // Authenticate
    err := c.Authenticate()
    if err != nil {
        panic(err)
    }
    // List all the containers
    containers, err := c.ContainerNames(nil)
    fmt.Println(containers)
    // etc...

Additions
---------

The `rs` sub project contains a wrapper for the Rackspace specific CDN Management interface.

Testing
-------

To run the tests you can either use an embedded fake Swift server
either use a real Openstack Swift server or a Rackspace Cloud files account.

When using a real Swift server, you need to set these environment variables
before running the tests

    export SWIFT_API_USER='user'
    export SWIFT_API_KEY='key'
    export SWIFT_AUTH_URL='https://url.of.auth.server/v1.0'

And optionally these if using v2 authentication

    export SWIFT_TENANT='TenantName'
    export SWIFT_TENANT_ID='TenantId'

And optionally these if using v3 authentication

    export SWIFT_TENANT='TenantName'
    export SWIFT_TENANT_ID='TenantId'
    export SWIFT_API_DOMAIN_ID='domain id'
    export SWIFT_API_DOMAIN='domain name'

And optionally these if using v3 trust

    export SWIFT_TRUST_ID='TrustId'

And optionally this if you want to skip server certificate validation

    export SWIFT_AUTH_INSECURE=1

And optionally this to configure the connect channel timeout, in seconds

    export SWIFT_CONNECTION_CHANNEL_TIMEOUT=60

And optionally this to configure the data channel timeout, in seconds

    export SWIFT_DATA_CHANNEL_TIMEOUT=60

Then run the tests with `go test`

License
-------

This is free software under the terms of MIT license (check COPYING file
included in this package).

Contact and support
-------------------

The project website is at:

- https://github.com/ncw/swift

There you can file bug reports, ask for help or contribute patches.

Authors
-------

- Nick Craig-Wood <nick@craig-wood.com>

Contributors
------------

- Brian "bojo" Jones <mojobojo@gmail.com>
- Janika Liiv <janika@toggl.com>
- Yamamoto, Hirotaka <ymmt2005@gmail.com>
- Stephen <yo@groks.org>
- platformpurple <stephen@platformpurple.com>
- Paul Querna <pquerna@apache.org>
- Livio Soares <liviobs@gmail.com>
- thesyncim <thesyncim@gmail.com>
- lsowen <lsowen@s1network.com>
- Sylvain Baubeau <sbaubeau@redhat.com>
- Chris Kastorff <encryptio@gmail.com>
- Dai HaoJun <haojun.dai@hp.com>
- Hua Wang <wanghua.humble@gmail.com>
- Fabian Ruff <fabian@progra.de>
- Arturo Reuschenbach Puncernau <reuschenbach@gmail.com>
- Petr Kotek <petr.kotek@bigcommerce.com>
- Stefan Majewsky <stefan.majewsky@sap.com>
- Cezar Sa Espinola <cezarsa@gmail.com>
- Sam Gunaratne <samgzeit@gmail.com>
- Richard Scothern <richard.scothern@gmail.com>
