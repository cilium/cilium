#!/bin/bash -e

git_checkout_ref() {
  local dir="$1"
  local ref="$2"
  git --work-tree="$dir" --git-dir="$dir/.git" checkout -q -f "$ref"
  git --work-tree="$dir" --git-dir="$dir/.git" clean -xdfq
}

if [ $# -lt 1 ] ; then
	echo "usage: $0 <TETRAGON_TAG>" 1>&2
	exit 1
fi

TAG=$1
VERSION="${TAG:1}"
if [ -f "tetragon-${VERSION}.tgz" ]; then
  echo "tetragon-${VERSION}.tgz already exists. Nothing to do."
  exit 0
fi

echo "Generating tetragon package from tag: $TAG"
rm -rf tetragon
git clone git@github.com:cilium/tetragon.git
git_checkout_ref "$(pwd)/tetragon" "$TAG"
helm package -d . tetragon/install/kubernetes --version="${VERSION}" --app-version="${VERSION}"
helm repo index . --merge index.yaml
./generate_readme.sh > README.md
git add README.md index.yaml tetragon-"$VERSION".tgz
git commit -s -m "Add tetragon $VERSION@$(cd tetragon; git rev-parse HEAD) ⎈"
./fix_dates.sh
git add index.yaml
git commit --amend --no-edit
