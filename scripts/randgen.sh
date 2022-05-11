#!/bin/sh
rand(){
    min=$1
    max=$(($2-$min+1))
    num=$(date +%s%N)
    echo $(($num%$max+$min))
}
sz=`rand 1024 2048`
var=`rand 512 1024 | md5sum | cut -c 1-$(rand 5 10)`
echo "long __attribute__((used,visibility (\"hidden\"),section(\".random\"))) __${var}__[${sz}];"
