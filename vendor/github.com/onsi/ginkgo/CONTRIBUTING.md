# Contributing to Ginkgo

Your contributions to Ginkgo are essential for its long-term maintenance and improvement.  To make a contribution:

- Please **open an issue first** - describe what problem you are trying to solve and give the community a forum for input and feedback ahead of investing time in writing code!
- Ensure adequate test coverage:
    - If you're adding functionality to the Ginkgo library, make sure to add appropriate unit and/or integration tests (under the `integration` folder).
    - If you're adding functionality to the Ginkgo CLI note that there are very few unit tests.  Please add an integration test.
    - Please run all tests locally (`ginkgo -r -p`) and make sure they go green before submitting the PR
    - Please run following linter locally `go vet ./...` and make sure output does not contain any warnings
- Update the documentation.  In addition to standard `godoc` comments Ginkgo has extensive documentation on the `gh-pages` branch.  If relevant, please submit a docs PR to that branch alongside your code PR.

Thanks for supporting Ginkgo!
