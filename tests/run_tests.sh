#!/bin/sh

FAIL=false

make check || FAIL=true
prove test*.sh || FAIL=true

if [ "${FAIL}" = "true" ]; then
  echo "Some tests FAILED"
  exit 2
fi

exit 0
