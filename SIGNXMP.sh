#!/bin/bash

Fname="$1"
if [ "$Fname" == "" ] ; then
  echo "Usage: $0 DestinationFile"
  echo "  e.g.: $0 ./test.jpg"
  exit
fi

# grab the file
cp regression/test-unsigned.jpg "$Fname"

# get the record
rec1=$(bin/sealtool -M '')
#echo "$rec1"

# insert the record into the file
# ExifTool doesn't want the start or end ticks
exiftool -config regression/exiftool-seal.config  -overwrite_original -SEAL="${rec1:6:-2}" "$Fname" > /dev/null 2>&1
if [ "$?" != "0" ] ; then
  echo "ExifTool failure."
  exit 1
fi

# get the digest
digest=$(bin/sealtool -v "$Fname" | grep '^ Digest: ' | awk '{print $2}')
#echo "$digest"

# get the record with the signature
rec2=$(bin/sealtool -M "$digest")
#echo "$rec2"

# re-insert
cp regression/test-unsigned.jpg "$Fname"
exiftool -config regression/exiftool-seal.config  -overwrite_original -SEAL="${rec2:6:-2}" "$Fname" > /dev/null 2>&1

# Now check it
bin/sealtool "$Fname"

