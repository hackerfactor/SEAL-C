#!/bin/bash
# End-to-End test suite for remote signing

# Everything is relative to this test directory.
cd $(dirname "$0")

FMT=""
if [ "$1" != "" ] ; then
  FMT=".$1"
  shift
fi

TESTDIR=test-remote-append.dir
rm -rf $TESTDIR
mkdir $TESTDIR

echo ""
echo "##### Append Test"
for ka in ec ; do
for sf in 'date3:hex' ; do
  sfname=${sf/:/_}
  count=0
  for i in ../regression/test-unsigned*"$FMT" ; do
	((count=$count+1))
	if [ $count -ge 10 ] ; then
		echo ""; echo "### Pausing..."; sleep 10;  # pause to prevent flooding the server
		count=0
	fi
	ext=${i##*.}
	if [ "$ext" == "zip" ] ; then continue ; fi # unsupported
	j=${i/..\/regression/$TESTDIR}
	out1=${j/-unsigned/-signed-remote-append1-$ka-$sfname}
	out2=${j/-unsigned/-signed-remote-append2-$ka-$sfname}
	out3=${j/-unsigned/-signed-remote-append3-$ka-$sfname}
	# create but leave open for appending
	echo ""
	../bin/sealtool -v -S --options append --ka "$ka" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out1" "$i"
	if [ "$?" != "0" ] ; then echo "Failed: $out1"; exit 1; fi
	echo ""
	../bin/sealtool -v --ka "$ka" "$out1"
	if [ "$?" != "0" ] ; then echo "Failed: $out1"; exit 1; fi
	# append
	echo ""
	../bin/sealtool -v -S --options append --ka "$ka" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out2" "$out1"
	if [ "$?" != "0" ] ; then echo "Failed: $out2"; exit 1; fi
	echo ""
	../bin/sealtool -v --ka "$ka" "$out2"
	# finalize
	echo ""
	../bin/sealtool -v -S --ka "$ka" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out3" "$out2"
	if [ "$?" != "0" ] ; then echo "Failed."; exit 1; fi
	echo ""
	../bin/sealtool -v --ka "$ka" "$out3"
	if [ "$?" != "0" ] ; then echo "Failed: $out3"; exit 1; fi
  done
done #sf
done # ka

echo "" ; echo "### Done"
exit 0
