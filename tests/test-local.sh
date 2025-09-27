#!/bin/bash
# End-to-End test suite for local signing

# Everything is relative to this $TESTDIRectory.
cd $(dirname "$0")

TESTDIR=test-local.dir
rm -rf $TESTDIR
mkdir $TESTDIR

echo "##### Local Key Generation Test"
for ka in rsa ec ; do
  # generate keys
  ../bin/sealtool -g --ka "$ka" -D "$TESTDIR/sign-$ka.dns" -k "$TESTDIR/sign-$ka.key" --genpass ''
  if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi
done # ka

echo ""
echo "##### Format Test"
for da in sha256 sha384 sha512 ; do
for ka in rsa ec ; do
  # iterate over signing formats
  for sf in 'hex' 'HEX' 'base64' 'date3:hex' 'date3:HEX' 'date3:base64' ; do
    sfname=${sf/:/_}

    # Test with local signing
    echo ""
    echo "#### Local Signing $da $ka $sf"
    echo ""
    for i in ../regression/test-unsigned*"$FMT" ; do
	ext=${i##*.}
	if [ "$ext" == "zip" ] ; then continue ; fi # unsupported right now

	j=${i/..\/regression/$TESTDIR}
	out=${j/-unsigned/-signed-local-$da-$ka-$sfname}
	../bin/sealtool -s -k "$TESTDIR/sign-$ka.key" --ka "$ka" --da "$da" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out" "$i"
	if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi
    done

    # Verify local signing
    echo ""
    echo "#### Verify Local $da $ka $sf"
    ../bin/sealtool --ka "$ka" --dnsfile "$TESTDIR/sign-$ka.dns" $TESTDIR/test-*local-$da-$ka-$sfname*
    if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi

  done #sf
done # ka
done # da

### PNG options
echo ""
echo "##### PNG Chunk Test"
for opt in seAl sEAl sEAL seAL teXt ; do
  i=../regression/test-unsigned.png
  ka=rsa
  sf="date3:base64"
  sfname=${sf/:/_}
  j=${i/..\/regression/$TESTDIR}
  out=${j/-unsigned/-signed-local-pngchunk-$opt-$ka-$sfname}
  echo ""
  ../bin/sealtool -v -s -k "$TESTDIR/sign-$ka.key" --options "$opt" --ka "$ka" --dnsfile "$TESTDIR/sign-$ka.dns" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out" "$i"
  if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi
  echo ""
  ../bin/sealtool -v --ka "$ka" --dnsfile "$TESTDIR/sign-$ka.dns" "$out"
  if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi
done

echo ""
echo "##### Append Test"
for ka in ec ; do
for sf in 'date3:hex' ; do
  sfname=${sf/:/_}
  for i in ../regression/test-unsigned*"$FMT" ; do
	ext=${i##*.}
	if [ "$ext" == "zip" ] ; then continue ; fi # unsupported right now

	j=${i/..\/regression/$TESTDIR}
	out1=${j/-unsigned/-signed-local-append1-$ka-$sfname}
	out2=${j/-unsigned/-signed-local-append2-$ka-$sfname}
	out3=${j/-unsigned/-signed-local-append3-$ka-$sfname}
	# create but leave open for appending
	echo ""
	../bin/sealtool -v -s -k "$TESTDIR/sign-$ka.key" --options append --ka "$ka" --dnsfile "$TESTDIR/sign-$ka.dns" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out1" "$i"
	if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi
	echo ""
	../bin/sealtool -v --ka "$ka" --dnsfile "$TESTDIR/sign-$ka.dns" "$out1"
	if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi
	# append
	echo ""
	../bin/sealtool -v -s -k "$TESTDIR/sign-$ka.key" --options append --ka "$ka" --dnsfile "$TESTDIR/sign-$ka.dns" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out2" "$out1"
	if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi
	echo ""
	../bin/sealtool -v --ka "$ka" --dnsfile "$TESTDIR/sign-$ka.dns" "$out2"
	# finalize
	echo ""
	../bin/sealtool -v -s -k "$TESTDIR/sign-$ka.key" --ka "$ka" --dnsfile "$TESTDIR/sign-$ka.dns" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out3" "$out2"
	if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi
	echo ""
	../bin/sealtool -v --ka "$ka" --dnsfile "$TESTDIR/sign-$ka.dns" "$out3"
	if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi
  done
done #sf
done # ka

### Src reference tests (local file)
echo ""
echo "##### Src Reference Test (local file)"

for da in sha256 sha512 ; do
for ka in rsa ec ; do
for srcsf in hex HEX base64 ; do
  srca="$da:$srcsf"
  echo ""
  echo "#### Local Signing with local src reference ($ka, $srca)"
  i=../regression/test-unsigned.jpg
  j=${i/..\/regression/$TESTDIR}
  out=${j/-unsigned/-signed-local-src-file-$ka-$da-$srcsf}
  ../bin/sealtool -s -k "$TESTDIR/sign-$ka.key" --ka "$ka" --da "$da" --srcf "../regression/test-unsigned.png" --srca "$srca" -o "$out" "$i"
  if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi

  echo "#### Verifying Local with local src reference ($ka, $srca)"
  ../bin/sealtool --ka "$ka" --dnsfile "$TESTDIR/sign-$ka.dns" "$out"
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
  echo "#### Local Signing with URL src reference ($ka, $srca)"
  i=../regression/test-unsigned.jpg
  j=${i/..\/regression/$TESTDIR}
  out=${j/-unsigned/-signed-local-src-url-$ka-$da-$srcsf}
  ../bin/sealtool -s -k "$TESTDIR/sign-$ka.key" --ka "$ka" --da "$da" --src "$src_url" --srca "$srca" -o "$out" "$i"
  if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi

  echo "#### Verifying Local with URL src reference ($ka, $srca)"
  ../bin/sealtool --ka "$ka" --dnsfile "$TESTDIR/sign-$ka.dns" "$out"
  if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi
done # srcsf
done # ka
done # da

### Try manual fields
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

exit 0
