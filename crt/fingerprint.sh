#!/bin/bash

sumcmd="sha1sum"
outcmd="openssl sha1 -hex"
incmd="openssl base64 -d "
files=( server_old.rsa server_1.rsa server_2.rsa server_3.rsa server_4.rsa )

pushd `dirname $0` > /dev/null

for f in ${files[@]}; do
echo "$f:"
cat $f | $incmd | $outcmd
#openssl rsa -RSAPublicKey_in -in $f -outform DER 2> /dev/null | $outcmd
done

popd > /dev/null
