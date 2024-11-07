#!/bin/bash

Field="$1"
Fname="$2"
if [ "$Fname" == "" ] ; then
  echo "Usage: $0 ExiftoolField DestinationFile"
  echo "  e.g.: $0 -Comment ./test.jpg"
  exit
fi

# grab the file
cp regression/test-unsigned.jpg "$Fname"

# get the record
rec1=$(bin/sealtool -M '')
#echo "$rec1"

# insert the record into the file
exiftool -overwrite_original "$Field=$rec1" "$Fname"
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
exiftool -overwrite_original "$Field=$rec2" "$Fname"

# Now check it
bin/sealtool "$Fname"

