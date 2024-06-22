#!/usr/bin/env bash
#
# Copyright 2016 The Kubernetes Authors All rights reserved.
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
#
# Provide a default $PROG (for use in most functions that use a $PROG: prefix
: ${PROG:="common"}
export PROG

##############################################################################
# Common library of useful functions and GLOBALS.
##############################################################################

set -o errtrace

# TODO:
# - Figure out a way to share common bits with other Kubernetes sub repos
# - cleanup / function headers

##############################################################################
# COMMON CONSTANTS
#
TOOL_LIB_PATH=${TOOL_LIB_PATH:-$(dirname $(readlink -ne $BASH_SOURCE))}
TOOL_ROOT=${TOOL_ROOT:-$(readlink -ne $TOOL_LIB_PATH/..)}
PATH=$TOOL_ROOT:$PATH
LOCAL_CACHE="/tmp/buildresults-cache.$$"
# Provide a default EDITOR for those that don't have this set
: ${EDITOR:="vi"}
export PATH TOOL_ROOT TOOL_LIB_PATH EDITOR

# Pretty curses stuff for terminals
if [[ -t 1 ]]; then
  # Set some video text attributes for use in error/warning msgs.
  declare -A TPUT=([BOLD]=$(tput bold 2>/dev/null))
  TPUT+=(
  [REVERSE]=$(tput rev 2>/dev/null)
  [UNDERLINE]=$(tput smul 2>/dev/null)
  [BLINK]=$(tput blink 2>/dev/null)
  [GREEN]=${TPUT[BOLD]}$(tput setaf 2 2>/dev/null)
  [RED]=${TPUT[BOLD]}$(tput setaf 1 2>/dev/null)
  [YELLOW]=${TPUT[BOLD]}$(tput setaf 3 2>/dev/null)
  [OFF]=$(tput sgr0 2>/dev/null)
  [COLS]=$(tput cols 2>/dev/null)
  )

  # HR
  HR="$(for ((i=1;i<=${TPUT[COLS]};i++)); do echo -en '\u2500'; done)"

  # Save original TTY State
  TTY_SAVED_STATE="$(stty -g)"
else
  HR="$(for ((i=1;i<=80;i++)); do echo -en '='; done)"
fi

# Set some usable highlighted keywords for functions like logrun -s
YES="${TPUT[GREEN]}YES${TPUT[OFF]}"
OK="${TPUT[GREEN]}OK${TPUT[OFF]}"
DONE="${TPUT[GREEN]}DONE${TPUT[OFF]}"
PASSED="${TPUT[GREEN]}PASSED${TPUT[OFF]}"
FAILED="${TPUT[RED]}FAILED${TPUT[OFF]}"
FATAL="${TPUT[RED]}FATAL${TPUT[OFF]}"
NO="${TPUT[RED]}NO${TPUT[OFF]}"
WARNING="${TPUT[YELLOW]}WARNING${TPUT[OFF]}"
ATTENTION="${TPUT[YELLOW]}ATTENTION${TPUT[OFF]}"
MOCK="${TPUT[YELLOW]}MOCK${TPUT[OFF]}"
FOUND="${TPUT[GREEN]}FOUND${TPUT[OFF]}"
NOTFOUND="${TPUT[YELLOW]}NOT FOUND${TPUT[OFF]}"

# Ensure USER is set
USER=${USER:-$LOGNAME}

# Set a PID for use throughout.
export PID=$$

# Save original cmd-line.
ORIG_CMDLINE="$*"

PROGSTATE=/tmp/$PROG-runstate

###############################################################################
# Define logecho() function to display to both log and stdout.
# As this is widely used and to reduce clutter, we forgo the common:: prefix
# Options can be -n or -p or -np/-pn.
# @optparam -p Add $PROG: prefix to stdout
# @optparam -r Exclude log prefix (used to output status' like $OK $FAILED)
# @optparam -n no newline (just like echo -n)
# @param a string to echo to stdout
logecho () {
  local log_prefix="$PROG::${FUNCNAME[1]:-"main"}(): "
  local prefix
  # Dynamically set fmtlen
  local fmtlen=$((${TPUT[COLS]:-"80"}))
  local n
  local raw=0
  #local -a sed_pat=()

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      -r) raw=1; shift ;;
      -n) n="-n"; shift ;;
      -p) prefix="$PROG: "; ((fmtlen+=${#prefix})); shift ;;
       *) break ;;
    esac
  done

  if ((raw)) || [[ -z "$*" ]]; then
    # Clean log_prefix for blank lines
    log_prefix=""
  #else
    # Increase fmtlen to account for control characters
    #((fmtlen+=$(echo "$*" grep -o '[[:cntrl:]]' |wc -l)))
    #sed_pat=(-e '2,${s}/^/ ... /g')
  fi

  # Allow widespread use of logecho without having to
  # determine if $LOGFILE exists first.
  [[ -f $LOGFILE ]] || LOGFILE="/dev/null"
  (
  # If -n is set, do not provide autoformatting or you lose the -n effect
  # Use of -n should only be used on short status lines anyway.
  if ((raw)) || [[ $n == "-n" ]]; then
    echo -e $n "$log_prefix$*"
  else
    # Add FUNCNAME to line prefix, but strip it from visible output
    # Useful for viewing log detail
    echo -e "$*" | fmt -$fmtlen | sed -e "1s,^,$log_prefix,g" "${sed_pat[@]}"
  fi
  ) | tee -a "$LOGFILE" |sed "s,^$log_prefix,$prefix,g"
}

###############################################################################
# logrun() function to run commands to both log and stdout.
# As this is widely used and to reduce clutter, we forgo the common:: prefix
#
# The calling function is added to the line prefix.
# NOTE: All optparam's for logrun() (obviously) must preceed the command string
# @optparam -v Run verbosely
# @optparam -s Provide a $OK or $FAILED status from running command
# @optparam -m MOCK command by printing out command line rather than running it.
# @optparam -r Retry attempts. Integer arg follows -r (Ex. -r 2)
#              Typically used together with -v to show retry attempts.
# @param a command string
# GLOBALS used in this function:
# * LOGFILE (Set by common::logfileinit()), if set, gets full command output
# * FLAGS_verbose (Set by caller - defaults to false), if true, full output to stdout
logrun () {
  local mock=0
  local status=0
  local arg
  local retries=0
  local try
  local retry_string
  local scope="::${FUNCNAME[1]:-main}()"
  local ret
  local verbose=0

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      -v) verbose=1; shift ;;
      -s) status=1; shift ;;
      -m) mock=1; shift ;;
      -r) retries=$2; shift 2;;
       *) break ;;
    esac
  done

  for ((try=0; try<=$retries; try++)); do
    if [[ $try -gt 0 ]]; then
      if ((verbose)) || ((FLAGS_verbose)); then
        # if global FLAGS_verbose, be very verbose
        logecho "Retry #$try..."
      elif ((status)); then
        # if we're reporting a status (-v), then just ...
        logecho -n "."
      fi
      # Add some minimal wait between retries assuming we're retrying due to
      # something resolvable by waiting 'just a bit'
      sleep 2
    fi

    # if no args, take stdin
    if (($#==0)); then
      if ((verbose)) || ((FLAGS_verbose)); then
        tee -a $LOGFILE
      else
        tee -a $LOGFILE &>/dev/null
      fi
      ret=$?
    elif [[ -f "$LOGFILE" ]]; then
      printf "\n$PROG$scope: %s\n" "$*" >> $LOGFILE

      if ((mock)); then
        logecho "($MOCK)"
        logecho "(CMD): $@"
        return 0
      fi

      # Special case "cd" which cannot be run through a pipe (subshell)
      if (! ((FLAGS_verbose)) && ! ((verbose)) ) || [[ "$1" == "cd" ]]; then
        "${@:-:}" >> $LOGFILE 2>&1
      else
        printf "\n$PROG$scope: %s\n" "$*"
        "${@:-:}" 2>&1 | tee -a $LOGFILE
      fi
    ret=${PIPESTATUS[0]}
    else
      if ((mock)); then
        logecho "($MOCK)"
        logecho "(CMD): $@"
        return 0
      fi

      if ((verbose)) || ((FLAGS_verbose)); then
        printf "\n$PROG$scope: %s\n" "$*"
        "${@:-:}"
      else
        "${@:-:}" &>/dev/null
      fi
      ret=${PIPESTATUS[0]}
    fi

    [[ "$ret" = 0 ]] && break
  done

  [[ -n "$retries" && $try > 0 ]] && retry_string=" (retry #$try)"

  if ((status)); then
    [[ "$ret" = 0 ]] && logecho -r "$OK$retry_string"
    [[ "$ret" != 0 ]] && logecho -r "$FAILED"
  fi

  return $ret
}

###############################################################################
# common::timestamp() Capture block timings and display them
# The calling function is added to the line prefix.
# NOTE: All optparam's for logrun() (obviously) must preceed the command string
# @param begin|end|done
# @optparam section defaults to main, but can be specified to time sub sections
common::timestamp () {
  local action=$1
  local section=${2:-main}
  # convert illegal characters to (legal) underscore
  section=${section//[-\.:\/]/_}
  local start_var="${section}start_seconds"
  local end_var="${section}end_seconds"
  local elapsed
  local d
  local h
  local m
  local s
  local prettyd
  local prettyh
  local prettym
  local prettys
  local pretty

  case $action in
  begin)

    # Get time(date) for display and calc.
    eval $start_var=$(date '+%s')

    # Print BEGIN message for $PROG.
    echo "$PROG: BEGIN $section on ${HOSTNAME%%.*} $(date)"

    if [[ $section == "main" ]]; then
      echo
    fi
    ;;
  end|done)
    # Check for "START" values before calcing.
    if [[ -z ${!start_var} ]]; then
      #display_time="EE:EE:EE - 'end' run without 'begin' in this scope or sourced script using common::timestamp"
      return 1
    fi

    # Get time(date) for display and calc.
    eval $end_var=$(date '+%s')

    elapsed=$(( ${!end_var} - ${!start_var} ))
    d=$(( elapsed / 86400 ))
    h=$(( (elapsed % 86400) / 3600 ))
    m=$(( (elapsed % 3600) / 60 ))
    s=$(( elapsed % 60 ))
    (($d>0)) && local prettyd="${d}d"
    (($h>0)) && local prettyh="${h}h"
    (($m>0)) && local prettym="${m}m"
    prettys="${s}s"
    pretty="$prettyd$prettyh$prettym$prettys"

    [[ $section == "main" ]] && echo
    echo "$PROG: DONE $section on ${HOSTNAME%%.*} $(date) in $pretty"
    ;;
  esac
}

# Write our own trap to capture signal
common::trap () {
  local func="$1"
  shift
  local sig

  for sig; do
    trap "$func $sig" "$sig"
  done
}

common::trapclean () {
  local sig=$1
  local frame=0

  # If user ^C's at read then tty is hosed, so make it sane again.
  [[ -n "$TTY_SAVED_STATE" ]] && stty "$TTY_SAVED_STATE"

  logecho;logecho
  logecho "Signal $sig caught!"
  logecho
  logecho "Traceback (line function script):"
  while caller $frame; do
    ((frame++))
  done
  common::exit 2 "Exiting..."
}

#############################################################################
# Clean exit with an ending timestamp
# @param Exit code
common::cleanexit () {
  # Display end common::timestamp when an existing common::timestamp begin
  # was run.
  [[ -n ${mainstart_seconds} ]] && common::timestamp end
  exit ${1:-0}
}

#############################################################################
# common::cleanexit() entry point with some formatting and message printing
# @param Exit code
# @param message
common::exit () {
  local etype=${1:-0}
  shift

  [[ -n "$1" ]] && (logecho;logecho "$@";logecho)
  common::cleanexit $etype
}

#############################################################################
# Simple yes/no prompt
#
# @optparam default -n(default)/-y/-e (default to n, y or make (e)xplicit)
# @param message
common::askyorn () {
  local yorn
  local def=n
  local msg="y/N"

  case $1 in
  -y) # yes default
      def="y" msg="Y/n"
      shift
      ;;
  -e) # Explicit
      def="" msg="y/n"
      shift
      ;;
  -n) shift
      ;;
  esac

  while [[ $yorn != [yYnN] ]]; do
    logecho -n "$*? ($msg): "
    read yorn
    : ${yorn:=$def}
  done

  # Final test to set return code
  [[ $yorn == [yY] ]]
}

# Save a specified number of backups to a file
common::rotatelog () {
  local file=$1
  local num=$2
  local tmpfile=/tmp/rotatelog.$PID
  local counter=$num

  # Quiet exit
  [[ ! -f "$file" ]] && return

  cp -p $file $tmpfile

  while ((counter>=0)); do
    if ((counter==num)); then
      rm -f $file.$counter
    elif ((counter==0)); then
      if [[ -f "$file" ]]; then
        next=$((counter+1))
        mv $file $file.$next
      fi
    else
      next=$((counter+1))
      [[ -f $file.$counter ]] && mv $file.$counter $file.$next
    fi
    ((counter==0)) && break
    ((counter--))
  done

  mv $tmpfile $file
}

# --norotate assumes you're passing in a unique LOGFILE.
# $2 then indicates the number of unique filenames prefixed up to the last
# dot extension that will be saved.  The rest of those files will be deleted
# For example, common::logfileinit --norotate foo.log.234 100
# common::logfileinit maintains up to 100 foo.log.* files.  Anything else named
# foo.log.* > 100 are removed.
common::logfileinit () {
  local nr=false

  if [[ "$1" == "--norotate" ]]; then
    local nr=true
    shift
  fi
  LOGFILE=${1:-$PWD/$PROG.log}
  local num=$2

  # Ensure LOG directory exists
  mkdir -p $(dirname $LOGFILE 2>&-)

  # Initialize Logfile.
  if ! $nr; then
    common::rotatelog "$LOGFILE" ${num:-3}
  fi
  # Truncate the logfile.
  > "$LOGFILE"

  echo "CMD: $PROG $ORIG_CMDLINE" >> "$LOGFILE"

  # with --norotate, remove the list of files that start with $PROG.log
  if $nr; then
    ls -1tr ${LOGFILE%.*}.* |head --lines=-$num |xargs rm -f
  fi
}

# An alternative that has a dependency on external program - pandoc
# store markdown man pages in companion files.  Allow prog -man to still read
# those and display a man page using:
# pandoc -s -f markdown -t man prog.md |man -l -
common::manpage () {
  [[ "$usage" == "yes" ]] && set -- -usage
  [[ "$man" == "yes" ]] && set -- -man
  [[ "$comments" == "yes" ]] && set -- -comments

  case $1 in
  -*usage|"-?")
    sed -n '/#+ SYNOPSIS/,/^#+ DESCRIPTION/p' $0 |sed '/^#+ DESCRIPTION/d' |\
     envsubst | sed -e 's,^#+ ,,g' -e 's,^#+$,,g'
    exit 1
    ;;
  -*man|-h|-*help)
    grep "^#+" "$0" |\
     sed -e 's,^#+ ,,g' -e 's,^#+$,,g' |envsubst |${PAGER:-"less"}
    exit 1
    ;;
  esac
}

###############################################################################
# General command-line parser converting -*arg="value" to $FLAGS_arg="value"
# Set -name/--name booleans to FLAGS_name=1
# As a convenience, flags can contain dashes or underscores, but dashes are
# converted to underscores in the final FLAGS_name to conform to variable
# naming standards.
# Sets global array POSITIONAL_ARGV holding all non-dash command-line arguments
common::namevalue () {
  local arg
  local name
  local value
  local -A arg_aliases=([v]="verbose" [n]="dryrun")

  for arg in "$@"; do
    case $arg in
      -*[[:alnum:]]*) # Strip off any leading - or --
          arg=$(printf "%s\n" $arg |sed 's/^-\{1,2\}//')
          # Handle global aliases
          arg=${arg_aliases[$arg]:-"$arg"}
          if [[ $arg =~ =(.*) ]]; then
            name=${arg%%=*}
            value=${arg#*=}
            # change -'s to _ in name for legal vars in bash
            eval export FLAGS_${name//-/_}=\""$value"\"
          else
            # bool=1
            # change -'s to _ in name for legal vars in bash
            eval export FLAGS_${arg//-/_}=1
          fi
          ;;
    *) POSITIONAL_ARGV+=("$arg")
       ;;
    esac
  done
}

###############################################################################
# Simple argc validation with a usage return
# @param num - number of POSITIONAL_ARGV that should be on the command-line
# return 1 if any number other than num
common::argc_validate () {
  local args=$1

  # Validate number of args
  if ((${#POSITIONAL_ARGV[@]}>args)); then
    logecho
    logecho "Exceeded maximum argument limit of $args!"
    logecho
    $PROG -?
    logecho
    common::exit 1
  fi
}

# Set a common::trap() to capture ^C's and other unexpected exits and do the
# right thing in common::trapclean().
common::trap common::trapclean ERR SIGINT SIGQUIT SIGTERM SIGHUP

# parse cmdline
common::namevalue "$@"

# Run common::manpage to show usage and man pages
common::manpage "$@"
