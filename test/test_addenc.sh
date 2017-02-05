#!/bin/bash

eval "../bin/genpkey -o private_keys.json -k 1024"
eval "../bin/extract -i private_keys.json -o public_key.json"

echo "'id',A','B','A+B','d(e(A+B))','error'" >> addenc.test

for i in `seq 1 500`;
    do
        NUM=`echo $(( $(( $RANDOM - $RANDOM )) % 10000000 ))` 
        DENOM=`echo $[$RANDOM % 1000]`
        A=`echo "${NUM}/${DENOM}" | bc -l`
        eval "../bin/encrypt -p private_keys.json -o A.enc -v ${A}"
        
        NUM=`echo $(( $(( $RANDOM - $RANDOM )) % 10000000 ))` 
        DENOM=`echo $[$RANDOM % 1000]`
        B=`echo "${NUM}/${DENOM}" | bc -l`
        eval "../bin/encrypt -p private_keys.json -o B.enc -v ${B}"
        
        C=`echo "${A} + ${B}" | bc -l`
        eval "../bin/addenc -p public_key.json -a A.enc -b B.enc -o C.enc"
        
        OUT=`eval "../bin/decrypt -p private_keys.json -c C.enc"`
        ERR=`echo "(($C)-($OUT))" | bc -l`
        echo "'${id}','${A}','${B}','${C}','${OUT}','${ERR}'" >> addenc.test
    done 

eval "rm A.enc"
eval "rm B.enc"
eval "rm C.enc"
eval "rm private_keys.json"
eval "rm public_key.json"