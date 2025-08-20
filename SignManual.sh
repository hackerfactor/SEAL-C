#!/bin/bash
# Sample code for manual signing using ExifTool

Field="$1"
Fname="$2"
if [ "$Fname" == "" ] ; then
  echo "Usage: $0 ExiftoolField DestinationFile"
  echo "  e.g.: $0 -Comment ./test.jpg"
  echo "  e.g.: $0 -EXIF:seal ./test.jpg"
  echo "  e.g.: $0 -XMP:seal ./test.jpg"
  exit
fi

# grab the file
cp regression/test-unsigned.jpg "$Fname"

# get the record
rec1=$(bin/sealtool -M '')
#echo "Rec1: $rec2"

# insert the record into the file
exiftool -config regression/exiftool-seal.config -overwrite_original "$Field=$rec1" "$Fname" > /dev/null 2>&1
if [ "$?" != "0" ] ; then
  echo "ExifTool failure."
  exit 1
fi

# get the digest
digest=$(bin/sealtool -v "$Fname" | grep -e '^ *Digest: ' | awk '{print $2}')
#echo "Digest: $digest"

# get the record with the signature
rec2=$(bin/sealtool -M "$digest")
#if [[ "$Field" == *XMP:* ]] ; then
#  rec2="${rec2}"
#fi
#echo "Rec2: $rec2"

# re-insert
cp regression/test-unsigned.jpg "$Fname"
exiftool -config regression/exiftool-seal.config -overwrite_original "$Field=$rec2" "$Fname" > /dev/null 2>&1
if [ "$?" != "0" ] ; then
  echo "ExifTool update failure."
  exit 1
fi

# Now check it
bin/sealtool "$Fname"
exit $?

