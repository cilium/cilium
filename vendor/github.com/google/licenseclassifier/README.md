# License Classifier

[![Build status](https://travis-ci.org/google/licenseclassifier.svg?branch=master)](https://travis-ci.org/google/licenseclassifier)

## Introduction

The license classifier is a library and set of tools that can analyze text to
determine what type of license it contains. It searches for license texts in a
file and compares them to an archive of known licenses. These files could be,
e.g., `LICENSE` files with a single or multiple licenses in it, or source code
files with the license text in a comment.

A "confidence level" is associated with each result indicating how close the
match was. A confidence level of `1.0` indicates an exact match, while a
confidence level of `0.0` indicates that no license was able to match the text.

## Adding a new license

Adding a new license is straight-forward:

1.  Create a file in `licenses/`.

    *   The filename should be the name of the license or its abbreviation. If
        the license is an Open Source license, use the appropriate identifier
        specified at https://spdx.org/licenses/.
    *   If the license is the "header" version of the license, append the suffix
        "`.header`" to it. See `licenses/README.md` for more details.

2.  Add the license name to the list in `license_type.go`.

3.  Regenerate the `licenses.db` file by running the license serializer:

    ```shell
    $ license_serializer -output licenseclassifier/licenses
    ```

4.  Create and run appropriate tests to verify that the license is indeed
    present.

## Tools

### Identify license

`identify_license` is a command line tool that can identify the license(s)
within a file.

```shell
$ identify_license LICENSE
LICENSE: GPL-2.0 (confidence: 1, offset: 0, extent: 14794)
LICENSE: LGPL-2.1 (confidence: 1, offset: 18366, extent: 23829)
LICENSE: MIT (confidence: 1, offset: 17255, extent: 1059)
```

### License serializer

The `license_serializer` tool regenerates the `licenses.db` archive. The archive
contains preprocessed license texts for quicker comparisons against unknown
texts.

```shell
$ license_serializer -output licenseclassifier/licenses
```

----
This is not an official Google product (experimental or otherwise), it is just
code that happens to be owned by Google.
