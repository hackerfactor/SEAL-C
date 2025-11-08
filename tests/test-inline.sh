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

echo "##### Local Inline Key Generation Test"
for ka in rsa ec ; do
  # generate keys
  ../bin/sealtool -g --ka "$ka" -D "$TESTDIR/sign-$ka.dns" -k "$TESTDIR/sign-$ka.key" --genpass '' -p
  if [ "$?" != "0" ] ; then echo "Failed to generate keys."; exit 1; fi
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
	j=${i/..\/regression/$TESTDIR}
	out=${j/-unsigned/-signed-local-inline-$da-$ka-$sfname}
	#echo "../bin/sealtool -s -p -k '$TESTDIR/sign-$ka.key' --ka '$ka' --da '$da' --sf '$sf' -o '$out' '$i'"
	../bin/sealtool -s -p -k "$TESTDIR/sign-$ka.key" --ka "$ka" --da "$da" --sf "$sf" -o "$out" "$i"
	rc="$?"
	if [ "$rc" != "0" ] ; then echo "Failed to sign. (rc=$rc)"; exit 1; fi
    done

    # Verify local signing
    echo ""
    echo "#### Verify Local Inline $da $ka $sf"
    #echo "../bin/sealtool --ka '$ka' --dnsfile '$TESTDIR/sign-$ka.dns' $TESTDIR/test-*local-inline-$da-$ka-$sfname*"
    ../bin/sealtool --ka "$ka" --dnsfile "$TESTDIR/sign-$ka.dns" $TESTDIR/test-*local-inline-$da-$ka-$sfname*
    rc="$?"
    if [ "$rc" != "0" ] ; then echo "Failed to verify local signing. (rc=$rc)"; exit 1; fi

    # Verify with --no-net (should fail to authenticate)
    echo ""
    echo "#### Verify Local Inline with --no-net $da $ka $sf"
    ../bin/sealtool --no-net $TESTDIR/test-*local-inline-$da-$ka-$sfname*
    rc="$?"
    # 8 = not authenticated. The signature is valid, but cannot be authenticated due to --no-net.
    if [ "$rc" != "8" ] ; then echo "Failed during no-net verify. Expected rc=8, got $rc."; exit 1; fi
  done #sf
done # ka
done # da
exit 0
