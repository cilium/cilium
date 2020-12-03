CustomVet
=========
CustomVet is a simple vet analysis tool that allows the Cilium
authors to vet the code in the cilium repository for scenarios
that we'd like to avoid.
An example is avoiding the use of the `time.After` function
within a loop in favor of our own `inctimer` package.
