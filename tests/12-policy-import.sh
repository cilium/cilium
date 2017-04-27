#!/bin/bash

source "./helpers.bash"

logs_clear

echo "------ simple policy import ------"

cat <<EOF | cilium -D policy import -
{
        "name": "foo"
}
EOF

read -d '' EXPECTED_POLICY <<"EOF" || true
{
  "name": "root",
  "children": {
    "foo": {
      "name": "foo"
    }
  }
}
EOF

DIFF=$(diff -Nru  <(cilium policy get root) <(echo "$EXPECTED_POLICY")) || true
if [[ "$DIFF" != "" ]]; then
	abort "$DIFF"
fi

cilium -D policy delete root
