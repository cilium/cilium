Contributing
============

If you wish to contribute to the Cilium project, feel encouraged to do
so.

Setting up the a development enviroment
---------------------------------------

Developer requirements
~~~~~~~~~~~~~~~~~~~~~~

You need to have the following tools available in order to effectively
contribute to Cilium:

- git
- go-swagger
  `go get -u github.com/go-swagger/go-swagger/cmd/swagger`
- go-bindata
  `go get -u github.com/jteeuwen/go-bindata/...`

Testsuite
---------

Please test all changes by running the testsuites. You have several options,
you can either run the vagrant provisioner *testsuite* as follows:

``$ vagrant provision --provision-with testsuite``

or you can ``vagrant ssh`` into the machine and then run the tests yourself:

``$ sudo make runtime-tests``

Submitting a pull request
-------------------------

Contributions may be submitted in the form of pull requests against the
github repository at: [https://github.com/cilium/cilium]

Before hitting the submit button, please make sure that the following
requirements have been met: \* The pull request and all corresponding
commits have been equipped with a well written commit message which
explains the reasoning and details of the change. \* You have added unit
and/or runtime tests where feasible. \* You have tested the changes and
checked for regressions by running the existing testsuite against your
changes. See the "Testsuite" section for additional details. \* You have
signed off on your commits, see the section "Developer's Certificate of
Origin" for more details.

Developer's Certificate of Origin
---------------------------------

To improve tracking of who did what, we've introduced a "sign-off"
procedure.

The sign-off is a simple line at the end of the explanation for the
commit, which certifies that you wrote it or otherwise have the right to
pass it on as open-source work. The rules are pretty simple: if you can
certify the below:

::

    Developer Certificate of Origin
    Version 1.1

    Copyright (C) 2004, 2006 The Linux Foundation and its contributors.
    1 Letterman Drive
    Suite D4700
    San Francisco, CA, 94129

    Everyone is permitted to copy and distribute verbatim copies of this
    license document, but changing it is not allowed.


    Developer's Certificate of Origin 1.1

    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.

then you just add a line saying::

::

    Signed-off-by: Random J Developer <random@developer.example.org>

using your real name (sorry, no pseudonyms or anonymous contributions.)
