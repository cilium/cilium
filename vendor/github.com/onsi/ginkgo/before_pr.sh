# Take current path
path=$(pwd)

# Split it
IFS='\/'; arrIN=($path); unset IFS;

# Find directory before ginkgo
len=${#arrIN[@]}

userDir=${arrIN[$len-2]}

# Replace onsi with userdir
find . -type f -name '*.go' -exec sed -i '' s/github.com\\/onsi\\/ginkgo\\/internal/github.com\\/$userDir\\/ginkgo\\/internal/ {} +