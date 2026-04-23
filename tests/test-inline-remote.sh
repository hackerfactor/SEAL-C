#!/bin/bash
# End-to-End test suite for remote signing

# Everything is relative to this test directory.
cd $(dirname "$0")

FMT=""
if [ "$1" != "" ] ; then
  FMT=".$1"
  shift
fi

TESTDIR=test-inline-remote.dir
rm -rf $TESTDIR
mkdir $TESTDIR

dig signmydata.com txt | grep ' p=' | sed -e 's@^.* ka=@@' -e 's@ .*p=@ @' -e 's@" "@@g' -e 's@"@@g' |
while read ka pk ; do
  echo "$pk" > "$TESTDIR/$ka.pk"
done


echo ""
echo "##### Format Test"
for da in sha256 sha384 sha512 ; do
for ka in rsa ec ; do
  pk=$(cat "$TESTDIR/$ka.pk")
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
	../bin/sealtool -p --pk "$pk" -S --da "$da" --ka "$ka" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out" "$i"
        if [ "$?" != "0" ] ; then echo "Failed: $out"; exit; fi
    done

    # Verify remote signing
    echo ""
    echo "#### Verify Remote $da $ka $sf"
    ../bin/sealtool $TESTDIR/test-*remote-$da-$ka-$sfname*
    if [ "$?" != "0" ] ; then echo "Failed: $TESTDIR/test-*remote-$da-$ka-$sfname*"; exit; fi

    echo ""; echo "### Pausing..."; sleep 10;  # pause to prevent flooding the server
  done #sf
done # ka
done # da

echo "" ; echo "### Done"
exit 0
