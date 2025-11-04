#!/bin/bash
# End-to-End test suite for inline public key signing

# Everything is relative to this test directory.
cd $(dirname "$0")

FMT=""
if [ "$1" != "" ] ; then
  FMT=".$1"
  shift
fi

TESTDIR=test-inline.dir
rm -rf $TESTDIR
mkdir $TESTDIR

echo "##### Local Key Generation Test"
for ka in rsa ec ; do
  # generate keys
  ../bin/sealtool -g --ka "$ka" -D "$TESTDIR/sign-$ka.dns" -k "$TESTDIR/sign-$ka.key" --genpass '' -p
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
    echo "#### Inline Local Signing $da $ka $sf"
    echo ""
    for i in ../regression/test-unsigned*"$FMT" ; do
	ext=${i##*.}
	if [ "$ext" == "zip" ] ; then continue ; fi # unsupported right now

	j=${i/..\/regression/$TESTDIR}
	out=${j/-unsigned/-signed-local-inline-$da-$ka-$sfname}
	../bin/sealtool -s -p -k "$TESTDIR/sign-$ka.key" --ka "$ka" --da "$da" --sf "$sf" -o "$out" "$i"
	if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi
    done

    # Verify local signing
    echo ""
    echo "#### Verify Local $da $ka $sf"
    ../bin/sealtool --ka "$ka" --dnsfile "$TESTDIR/sign-$ka.dns" $TESTDIR/test-*local-inline-$da-$ka-$sfname*
    if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi

  done #sf
done # ka
done # da

exit 0
