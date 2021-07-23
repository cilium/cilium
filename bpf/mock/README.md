## Dependencies

You do not have to install the following dependencies because there is a
container provided.

[CMock](https://github.com/ThrowTheSwitch/CMock)

CMock is a mock and stub generator and runtime for unit testing C. We avoid
using C++ mocking frameworks because of some style difference between C and C++.

[Ruby](https://www.ruby-lang.org/)

Ruby is a common programming language. Since CMock relies on Ruby to generate mock
libraries, it is necessary to install Ruby first.

## Creating Unit Tests

### Generating Mock Libraries

Check if the mock libraries for the helper functions are up to date and follow
the instructions:

```bash
make -C bpf/mock check_helper_headers
```

If the mock libraries for the helper functions are out of date, run

```bash
make -C bpf/mock generate_helper_headers
```

or manually add the new helpers to mock/helpers.h, then run


```bash
make -C bpf/mock mock_helpers
```

to generate mock libraries for the helpers.

If there is a need to mock customized functions, first create a header
containing the declarations of the functions to be mocked, then run

```bash
make -C bpf/mock mock_customized filename=NAME_OF_THE_HEADER_TO_BE_MOCKED
```

to generate mock library for them.

There is a demo header conntrack\_stub.h inside the current directory containing the declarations of the functions in lib/conntrack.h, run

```bash
make -C bpf/mock mock_customized filename=conntrack_stub.h
```

to generate the corresponding mock library.

### Creating a Test Program

For the details on how to make use of mock libraries, see [CMock: A Summary](https://github.com/ThrowTheSwitch/CMock/blob/master/docs/CMock_Summary.md).

There is a demo test program nat\_test.h in Cilium/bpf/tests/.

## Run Unit Tests

### Compiling and Linking

To compile and link all the related files into an executable file, create a C
file that calls the test functions.

There is a demo C file nat-test.c in Cilium/test/bpf/ and a target nat-test in
the Makefile, run

```bash
make -C test/bpf nat-test
```

to produce a demo executable file.

The rule of the target nat-test in Makefile can be referred to create
self-defined tests.
