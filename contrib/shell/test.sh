#!/bin/bash
# Copyright 2017-2019 Authors of Cilium
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

readonly t_reset=$(tput sgr0)
readonly red=$(tput bold; tput setaf 1)
readonly green=$(tput bold; tput setaf 2)
readonly yellow=$(tput bold; tput setaf 3)

# Watch a file or directory for changes and trigger some action at that time.
#
# $1 = File to watch
# $2+ = Command and arguments
function watchdo
{
    local FILE=$1
    shift

    if [ ! -z "$TESTPKGS" ]; then
        echo -e "${yellow}Using TESTPKGS=\"$TESTPKGS\" for run.${t_reset}"
    fi
    echo -e "${yellow}Running \"$@\" on changes to \"$FILE\" ...${t_reset}"
    while inotifywait -q -r -e move $FILE; do
        eval "$@";
        if [ $? == 0 ] ; then
            echo -e "${yellow}$@${t_reset}: ${green}✔${t_reset}"
        else
            echo -e "${yellow}$@${t_reset}: ${red}✘${t_reset}"
        fi
    done
}

function watchtest_
{

    watchdo "." "make --quiet build unit-tests"
}

# Watch a file or directory for changes and trigger tests when it is modified.
#
# $1 = Filepath to watch under cilium directory
function watchtest
{
    if [ $# -gt 1 ]; then
        echo "usage: $0 <package>"
        exit 1
    elif ! which inotifywait >/dev/null; then
        echo "Cannot find 'inotifywait'. Please install inotify-tools."
        exit 1
    elif [ $# -eq 1 ]; then
        TESTPKGS="$1" watchtest_
    else
        watchtest_
    fi
}
