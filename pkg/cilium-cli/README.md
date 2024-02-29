# Isovalent Enterprise for Cilium CLI

Isovalent Enterprise for Cilium CLI extends the OSS [cilium-cli] by adding
connectivity tests and sysdump tasks that are specific to Isovalent Enterprise
for Cilium. Isovalent Enterprise for Cilium CLI replaces the
github.com/cilium/cilium dependency with github.com/isovalent/cilium in
[go.mod]. This enables you to write connectivity tests using the Isovalent
Enterprise for Cilium.

This version of cilium-cli is currently used in [enterprise-kind.yaml].

[cilium-cli]: https://github.com/cilium/cilium-cli
[enterprise-kind.yaml]: /.github/workflows/enterprise-kind.yaml
[go.mod]: go.mod
