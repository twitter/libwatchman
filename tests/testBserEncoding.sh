#!/bin/bash

set -o nounset
set -o errexit

TEST_DIR=t

TESTS=$(cd ${TEST_DIR}; ls -1 *.json)
NUM_TESTS=$(echo ${TESTS} | wc -w | awk '{print $1}')

echo "1..${NUM_TESTS}"

for json in ${TESTS}; do
    OUT=${json%.*}.bser.out
    GOLD=${TEST_DIR}/${json%.*}.bser
    if [ ! -f ${GOLD} ]; then
        echo "not ok -- Missing gold result file: ${GOLD}"
    else
       ./json2bser < ${TEST_DIR}/${json} 2>/dev/null | xxd -ps > ${OUT}
       RESULT=$(diff ${OUT} ${GOLD} 2>&1 >/dev/null || echo "fail")
       if [ "$RESULT" = "fail" ]; then
           echo "not ok -- result did not match gold file: ${GOLD}"
       else
           echo "ok"
           rm ${OUT}
       fi
   fi
done
