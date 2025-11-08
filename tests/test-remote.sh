#!/bin/bash
# End-to-End test suite for remote signing

# Everything is relative to this test directory.
cd $(dirname "$0")

FMT=""
if [ "$1" != "" ] ; then
  FMT=".$1"
  shift
fi

TESTDIR=test-remote.dir
rm -rf $TESTDIR
mkdir $TESTDIR

echo ""
echo "##### Format Test"
for da in sha256 sha384 sha512 ; do
for ka in rsa ec ; do
  # iterate over signing formats
  for sf in 'hex' 'HEX' 'base64' 'date3:hex' 'date3:HEX' 'date3:base64' ; do
    sfname=${sf/:/_}

    # Test with remote signing
    echo ""
    echo "#### Remote Signing $da $ka $sf"
    for i in ../regression/test-unsigned*"$FMT" ; do
	ext=${i##*.}

	j=${i/..\/regression/$TESTDIR}
	out=${j/-unsigned/-signed-remote-$da-$ka-$sfname}
	../bin/sealtool -S --da "$da" --ka "$ka" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out" "$i"
        if [ "$?" != "0" ] ; then echo "Failed."; exit; fi
    done

    # Verify remote signing
    echo ""
    echo "#### Verify Remote $da $ka $sf"
    ../bin/sealtool $TESTDIR/test-*remote-$da-$ka-$sfname*
    if [ "$?" != "0" ] ; then echo "Failed."; exit; fi

  done #sf
done # ka
done # da

### Src reference tests (local file)
echo ""
echo "##### Src Reference Test (local file)"

for da in sha256 sha512 ; do
for ka in rsa ec ; do
for srcsf in hex HEX base64 ; do
  srca="$da:$srcsf"
  echo ""
  echo "#### Remote Signing with local src reference ($ka, $srca)"
  i=../regression/test-unsigned.jpg
  j=${i/..\/regression/$TESTDIR}
  out=${j/-unsigned/-signed-local-src-file-$ka-$da-$srcsf}
  ../bin/sealtool -S --da "$da" --ka "$ka" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" --srcf "../regression/test-unsigned.png" --srca "$srca" -o "$out" "$i"
  if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi
  ../bin/sealtool --srcf "../regression/test-unsigned.png" $TESTDIR/test-*remote-$da-$ka-$sfname*
  if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi

  # Verify remote signing
  echo ""
  echo "#### Verify Remote $da $ka $sf"
  ../bin/sealtool $TESTDIR/test-*remote-$da-$ka-$sfname*
  if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi

done # srcsf
done # ka
done # da

### Src reference tests (URL)
echo ""
echo "##### Src Reference Test (URL)"

for da in sha256 sha512 ; do
for ka in rsa ec ; do
for srcsf in hex HEX base64 ; do
  srca="$da:$srcsf"
  src_url="https://signmydata.com/?logo=seal-fingerprint.jpeg"
  echo ""
  echo "#### Remote Signing with URL src reference ($ka, $srca)"
  i=../regression/test-unsigned.jpg
  j=${i/..\/regression/$TESTDIR}
  out=${j/-unsigned/-signed-local-src-url-$ka-$da-$srcsf}
  ../bin/sealtool -S --da "$da" --ka "$ka" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" --src "$src_url" --srca "$srca" -o "$out" "$i"
  if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi
  ../bin/sealtool "$out"
  if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi

  # Verify remote signing
  echo ""
  echo "#### Verify Remote $da $ka $sf"
  ../bin/sealtool $TESTDIR/test-*remote-$da-$ka-$sfname*
  if [ "$?" != "0" ] ; then echo "Failed."; exit; fi

done # srcsf
done # ka
done # da

exit 0
