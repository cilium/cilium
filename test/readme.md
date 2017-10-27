# Cilium Test Suite

Cilium test suite is based on [Ginkgo test
framework](https://onsi.github.io/ginkgo/), before start writing test, maybe it
is a good idea to read [Ginkgo
Quickstart](https://onsi.github.io/ginkgo/#getting-started-writing-your-first-test)
guide and run this [test suite
example](https://github.com/onsi/composition-ginkgo-example) written by the
[Ginkgo creator](https://github.com/onsi/).

So, before writing test, we should understand the test suite flavors that have
the system:

- Runtime: This is the flavor where all cilium features are tested.
- K8S: This is the flavor that we use to test Kubernetes specified features.

Each flavor will power on a new virtual server (vagrant box), ginkgo will
connect to this server using ssh and run the test specified for that flavor.

To detect what flavor we are going to run, `BeforeSuite` in the test_suite.go
will identify the scope based on the focus flag string, and it will power on
the specified server

When the server is power on, the normal execution of the test will start. On
each spec, a new ssh connection will be open to the virtual server. Mainly this
connections are wrapped in some helpers, and a Node attribute is exported in
case that we need to run a specific command on a node.


## Requirements

Before run any test, you should have the following tools installed.

- Virtualbox 5.1
- Vagrant 2.0
- Docker >=1.13
- Docker-compose >=1.16
- Ginkgo `go get github.com/onsi/ginkgo/ginkgo`
- Gomega `go get github.com/onsi/gomega`

## Runtime Test:

Runtime test is where all features are tested. It is provisioned based on a
[ubuntu 17.04 server with all cilium dependencies already in
place](https://github.com/eloycoto/cilium_basebox).

To run these tests, a --focus flag need to be provided in the Ginkgo command,
if the focus flag start with  "Run" the system will create runtime vagrant
box. You can see the status of the box using the following command:

```
cd test; vagrant status runtime
````

To run the test, you need to execute the following command:
```
cd test; ginkgo --focus "Run"
```

After you run this, you will see the result of each test in your terminal until
the finish.

If you want to run one specified test, you have two options:

1) Add the prefix FIT on the test; this marks the test as focussed, Ginkgo will
skip another test, and it will run only the focussed test.
```
	It("Example test", func(){
		Expect(true).Should(BeTrue())
	})

	FIt("Example focussed test", func(){
		Expect(true).Should(BeTrue())
	})
```

2)  In case that you want  to run using the command line options, you can do
the following:

```
ginkgo --focus "Run*" --focus "L7 "
```

This will focus on Run* and start the "Runtime" scope, and it will run the
test that starts with "L7"

## Kubernetes Flavor

Similar to runtime test, but here only test features related with the
Kubernetes integration. The main difference from runtime test is that K8s uses
two servers to test the connectivity between different containers.  To run the
test a focus flag needs to be provided:

```
ginkgo --focus "K8S*" --focus "L7 "
```

In the other hand, Kubernetes test has an option to test in a different
version. This can be achieved if you export an env variable before test starts
`EXPORT K8S_VERSION=1.6`


## Reporting
By default Ginkgo report to a custom reporter to the os.Stdout, but JUnit
reported is set so each time that the test is generated two files will be
created with the test results:

- runtime.xml: -> with the results of the runtime test.
- K8s.xml -> with the kubernetes testing results.

## FAQ:

### Who is using Ginkgo?

- [Kubernetes
  e2e](https://github.com/kubernetes/kubernetes/tree/master/test/e2e) is using
  Ginkgo
- CloudFoundry is using Ginkgo, and they [presented
  it](https://www.youtube.com/watch?v=rGHu8IvGzNM).

### How can I run the test in a  different K8s version?

On Vagrantfile, we have an ENV variable that selects the K8S version, so to run
specific K8s version you should run the following:

```
cd test; K8S_VERSION=1.6 ginkgo --focus="K8s*" -v -noColor'
```
