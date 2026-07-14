# MCS Conformance Tests

This package contains the MCS API conformance suite. It is intended for MCS
implementations to run against real clusters and generates `report.yaml` and
`report.html` files. To produce valid results, the conformance suite needs to
run against two or more clusters.

## Run

Install your MCS implementation and make sure your kubeconfig has contexts that
can access the clusters you want to test against.

Then run the tests with the following command, replacing `cluster-a` and
`cluster-b` with the correct context names:

```sh
cd conformance
go test . -args -contexts=cluster-a,cluster-b
```

The conformance suite uses Ginkgo/Gomega, which provides various flags in
addition to the conformance specific flags. Pass `-args -help` to see all the
available flags.

You can also import and integrate the conformance tests into your Go project
like [Cilium does](https://github.com/cilium/cilium/blob/main/pkg/clustermesh/mcsapi/conformance/conformance_test.go).

## Submit Results

After running the conformance tests, you can submit the generated
`report.yaml` on behalf of your MCS implementation. See
[the submission instructions](https://github.com/kubernetes-sigs/sig-multicluster-site/blob/main/site-src/implementations/mcs-implementations/reports/README.md)
for more details.
