#!/bin/bash

set -e

TMPDIR=`mktemp -d`

function cleanup {
	rm -r $TMPDIR
	rm $CLANG_FILE 2> /dev/null
}
trap cleanup EXIT

cd $TMPDIR

CLANG_DIR="clang+llvm-3.8.1-x86_64-linux-gnu-ubuntu-16.04"
CLANG_FILE="${CLANG_DIR}.tar.xz"
CLANG_URL="http://releases.llvm.org/3.8.1/$CLANG_FILE"
CLANGROOT=/usr/local/clang

if [ -d "/usr/local/$CLANG_DIR" ]; then
	echo "Existing clang installation found."
	echo "Removing old installation..."
	rm -rf /usr/local/$CLANG_DIR
fi

wget $CLANG_URL
mkdir -p /usr/local
tar -C /usr/local -xJf $CLANG_FILE
ln -s /usr/local/$CLANG_DIR $CLANGROOT

echo "Please add $CLANGROOT/bin to your \$PATH"
