#!/bin/bash

# based on https://stackoverflow.com/a/1985512/563158

LOCKFILE="/var/lock/$(basename "$0")"
LOCKFD=99

_lock()             { flock -"$1" "$LOCKFD";  }
_no_more_locking()  { _lock u; _lock xn && rm -f "$LOCKFILE";  }
_prepare_locking()  { eval "exec $LOCKFD>\"$LOCKFILE\""; trap _no_more_locking EXIT;  }

_prepare_locking

lock()            { _lock x;  }   # obtain a lock
unlock()            { _lock u;  }   # drop a lock
