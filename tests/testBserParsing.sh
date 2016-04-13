#!/bin/bash

set -o nounset
set -o errexit

mktight() {
    local readonly in=$1
    local readonly out=$2

    cat ${in} | tr '\n\t' ' ' | sed -e 's/ //g' > ${out}
}

TEST_DIR=t

TESTS=$(cd ${TEST_DIR}; ls -1 *.bser)
NUM_TESTS=$(echo ${TESTS} | wc -w | awk '{print $1}')

echo "1..${NUM_TESTS}"

for bser in ${TESTS}; do
    OUT=${bser%.*}.json.out
    GOLD=${TEST_DIR}/${bser%.*}.json
    if [ ! -f ${GOLD} ]; then
        echo "not ok -- Missing gold result file: ${GOLD}"
    else
       xxd -r -p ${TEST_DIR}/${bser} |./bser2json 2>/dev/null > ${OUT}
       mktight ${OUT} ${OUT}.tight
       mktight ${GOLD} ${GOLD}.tight
       RESULT=$(diff -w ${OUT}.tight ${GOLD}.tight 2>&1 >/dev/null || echo "fail")
       rm -f ${OUT}.tight ${GOLD}.tight
       if [ "$RESULT" = "fail" ]; then
           echo "not ok -- result did not match gold file: ${GOLD}"
       else
           echo "ok"
           rm ${OUT}
       fi
   fi
done
