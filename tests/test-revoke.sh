#!/bin/bash
# End-to-End test suite for remote signing
# Handles regression testing

# Everything is relative to this test directory.
cd $(dirname "$0")

FMT=""
if [ "$1" != "" ] ; then
  FMT=".$1"
  shift
fi

TESTDIR=test-revoke.dir
rm -rf $TESTDIR
mkdir $TESTDIR

echo ""
echo "##### Format Test"
for da in sha256 ; do
for ka in ec ; do
# iterate over signing formats
for sf in 'base64' 'date3:base64' ; do
  sfname=${sf/:/_}
  for testnum in test0 test1 test2 test3 ; do

    # Test with remote signing
    echo ""
    echo "#### Remote Signing with Revocation $da $ka $sf"
    for i in ../regression/test-unsigned*"$FMT" ; do
	ext=${i##*.}

	j=${i/..\/regression/$TESTDIR}
	out=${j/-unsigned/-signed-$testnum-$da-$ka-$sfname}
	../bin/sealtool -S --testdomain "$testnum.revoke.signmydata.com" --da "$da" --ka "$ka" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out" "$i"
	rc="$?"
        if [ "$rc" != "0" ] ; then echo "Failed signing (rc=$rc)."; exit; fi
    done

    # Verify remote signing
    echo ""
    echo "#### Verify Remote $da $ka $sf"
    ../bin/sealtool $TESTDIR/test-*-$testnum-$da-$ka-$sfname*
    rc="$?"

    ## test0 does not exist and should not validate (not revoke)
    if [ "$testnum" == "test0" ] ; then
	if [ "$rc" != "4" ] ; then echo "Failed to not validate (rc=$rc)."; exit; fi
    ## test1 uses a global revoke
    elif [ "$testnum" == "test1" ] ; then
	# 17 = 0x11 = revoked + not validated
	if [ "$rc" != "17" ] ; then echo "Failed to global revoke (rc=$rc)."; exit; fi
    ## test2..testn revoke specific certs
	# 16 = 0x10 = revoked + validated
    elif [ "$rc" != "16" ] ; then echo "Failed revoke (rc=$rc)."; exit; fi
  done # testnum
done #sf
done # ka
done # da

exit 0
