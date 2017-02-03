#!/bin/bash

eval "../bin/genpkey -o private_keys.json -k 1024"
eval "../bin/extract -i private_keys.json -o public_key.json"

echo "'plain','decrypt','error'" >> encrypt.test

for i in `seq 1 100`;
    do
        NUM=`echo $(( $(( $RANDOM - $RANDOM )) % 10000000 ))` 
        DENOM=`echo $[$RANDOM % 1000]`
        IN=`echo "${NUM}/${DENOM}" | bc -l`
        eval "../bin/encrypt -p private_keys.json -o X.enc -v ${IN}"
        OUT=`eval "../bin/decrypt -p private_keys.json -c X.enc"`
        ERR=`echo "(($IN)-($OUT))" | bc -l`
        echo "'${IN}','${OUT}','${ERR}'" >> encrypt.test
    done 

eval "rm X.enc"
eval "rm private_keys.json"
eval "rm public_key.json"