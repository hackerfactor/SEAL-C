#!/bin/bash
# End-to-End test suite for local signing

##################################
# Check for dependencies
##################################
command -v exiftool >/dev/null 2>&1
if [ $? != 0 ] ; then
  echo "ERROR: exiftool not installed."
  echo "Install exiftool from https://exiftool.org/"
  exit 1
fi

# Ensure it's the correct version
exifver=$(exiftool -ver)
awk -v var="$exifver" -v val="13.03" 'BEGIN { exit (var < val ? 0 : 1) }' > /dev/null 2>&1
if [ $? == 0 ] ; then
  echo "ERROR: exiftool too old; found version $exifver, need 13.03 or later."
  echo "Install exiftool from https://exiftool.org/"
  exit 1
fi

##################################
# Everything is relative to this test directory.
##################################
cd $(dirname "$0")

TESTDIR=test-manual.dir
rm -rf $TESTDIR
mkdir $TESTDIR

### Try manual fields
if [ "$FMT" == "" ] || [ "$FMT" == ".jpg" ] ; then
  echo ""
  echo "##### Manual Test"
  echo ""
  echo "#### Manual Non-standard JPEG comment"
  ./SignManual.sh -Comment $TESTDIR/test-signed-remote-manual-comment.jpg
  if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi

  echo ""
  echo "#### Manual EXIF"
  ./SignManual.sh -EXIF:seal $TESTDIR/test-signed-remote-manual-exif.jpg
  if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi

  echo ""
  echo "#### Manual XMP"
  ./SignManual.sh -XMP:seal $TESTDIR/test-signed-remote-manual-xmp.jpg
  if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi
fi

exit 0
