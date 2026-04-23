#!/bin/bash
# End-to-End test suite for remote signing

# Everything is relative to this test directory.
cd $(dirname "$0")

FMT=""
if [ "$1" != "" ] ; then
  FMT=".$1"
  shift
fi

TESTDIR=test-srcref.dir
rm -rf $TESTDIR
mkdir $TESTDIR

### Src reference tests
echo ""
echo "##### Src Reference Test"

for da in sha256 sha512 ; do
for ka in rsa ec ; do
for sf in 'hex' 'HEX' 'base64' 'date3:hex' 'date3:HEX' 'date3:base64' ; do
for srcsf in hex HEX base64 ; do
  srca="$da:$srcsf"
  echo ""
  echo "#### Remote Signing with src reference ($ka, $srca)"
  i=../regression/test-unsigned.jpg
  j=${i/..\/regression/$TESTDIR}
  out=${j/-unsigned/-srcfile-$ka-$da-$sf-$srcsf}
  ../bin/sealtool -S --da "$da" --ka "$ka" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" --srcf "../regression/test-unsigned.png" --srca "$srca" -o "$out" "$i"
  if [ "$?" != "0" ] ; then echo "Failed: $out"; exit 1; fi
done # srcsf
done # sf

  # Verify remote signing
  echo "#### Verify Remote (local file)"
  ../bin/sealtool --srcf "../regression/test-unsigned.png" $TESTDIR/test-srcfile-$ka-$da-*
  if [ "$?" != "0" ] ; then echo "Failed"; exit 1; fi

  echo ""; echo "### Pausing..."; sleep 10;  # pause to prevent flooding the server
done # ka
done # da

### Src reference tests (URL)
echo ""
echo "##### Src Reference Test (URL)"

for da in sha256 sha512 ; do
for ka in rsa ec ; do
for sf in 'hex' 'HEX' 'base64' 'date3:hex' 'date3:HEX' 'date3:base64' ; do
for srcsf in hex HEX base64 ; do
  srca="$da:$srcsf"
  src_url="https://signmydata.com/?logo=seal-fingerprint.jpeg"
  echo ""
  echo "#### Remote Signing with URL src reference ($ka, $srca)"
  i=../regression/test-unsigned.jpg
  j=${i/..\/regression/$TESTDIR}
  out=${j/-unsigned/-srcurl-$ka-$da-$sf-$srcsf}
  ../bin/sealtool -S --da "$da" --ka "$ka" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" --src "$src_url" --srca "$srca" -o "$out" "$i"
  if [ "$?" != "0" ] ; then echo "Failed: $out"; exit 1; fi
done # srcsf
done # sf
  echo "#### Verify Remote URL"
  ../bin/sealtool --srcf "../regression/test-unsigned.png" $TESTDIR/test-srcurl-$ka-$da-*
  if [ "$?" != "0" ] ; then echo "Failed"; exit 1; fi

  echo ""; echo "### Pausing..."; sleep 10;  # pause to prevent flooding the server
  # Verify remote signing
done # ka
done # da

echo "" ; echo "### Done"
exit 0
