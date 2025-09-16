#!/bin/bash

rm -rf test.dir
mkdir test.dir

ISLOCAL=1
ISREMOTE=1
ISFINAL=1
ISAPPEND=1
ISONLYMANUAL=0

FMT=""
while [ "$1" != "" ] ; do
  if [ "$1" == "local" ] ; then ISREMOTE=0
  elif [ "$1" == "remote" ] ; then ISLOCAL=0
  elif [ "$1" == "final" ] ; then ISAPPEND=0
  elif [ "$1" == "append" ] ; then ISFINAL=0
  elif [ "$1" == "onlymanual" ] ; then ISONLYMANUAL=1
  else
    FMT=".$1"
  fi
  shift
done

if [ $ISLOCAL == 1 ] && [ $ISONLYMANUAL == 0 ] ; then
  echo "##### Local Key Generation Test"
  for ka in rsa ec ; do
    # generate keys
    bin/sealtool -g --ka "$ka" -D "test.dir/sign-$ka.dns" -k "test.dir/sign-$ka.key" --genpass ''
    if [ "$?" != "0" ] ; then exit ; fi
  done # ka
fi

if [ $ISFINAL == 1 ] && [ $ISONLYMANUAL == 0 ] ; then
echo ""
echo "##### Format Test"
for da in sha256 sha384 sha512 ; do
for ka in rsa ec ; do
  # iterate over signing formats
  for sf in 'hex' 'HEX' 'base64' 'date3:hex' 'date3:HEX' 'date3:base64' ; do
    sfname=${sf/:/_}

    # Test with local signing
    if [ $ISLOCAL == 1 ] ; then
      echo ""
      echo "#### Local Signing $da $ka $sf"
      echo ""
      for i in regression/test-unsigned*"$FMT" ; do
	ext=${i##*.}
	if [ "$ext" == "zip" ] ; then continue ; fi # unsupported right now

	j=${i/regression/test.dir}
	out=${j/-unsigned/-signed-local-$da-$ka-$sfname}
	bin/sealtool -s -k "test.dir/sign-$ka.key" --ka "$ka" --da "$da" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out" "$i"
	if [ "$?" != "0" ] ; then exit; fi
      done

      # Verify local signing
      echo ""
      echo "#### Verify Local $da $ka $sf"
      bin/sealtool --ka "$ka" --dnsfile "test.dir/sign-$ka.dns" test.dir/test-*local-$da-$ka-$sfname*
      if [ "$?" != "0" ] ; then exit; fi
    fi

    # Test with remote signing
    if [ $ISREMOTE == 1 ] ; then
      echo ""
      echo "#### Remote Signing $da $ka $sf"
      for i in regression/test-unsigned*"$FMT" ; do
	ext=${i##*.}
	if [ "$ext" == "zip" ] ; then continue ; fi # unsupported right now

	j=${i/regression/test.dir}
	out=${j/-unsigned/-signed-remote-$da-$ka-$sfname}
	bin/sealtool -S --da "$da" --ka "$ka" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out" "$i"
        if [ "$?" != "0" ] ; then exit; fi
      done

      # Verify remote signing
      echo ""
      echo "#### Verify Remote $da $ka $sf"
      bin/sealtool test.dir/test-*remote-$da-$ka-$sfname*
      if [ "$?" != "0" ] ; then exit; fi
    fi

  done #sf
done # ka
done # da
fi

### PNG options
if [ $ISONLYMANUAL == 0 ] ; then
  if [ "$FMT" == "" ] || [ "$FMT" == ".png" ] ; then
    if [ $ISLOCAL == 1 ] && [ $ISFINAL == 1 ] ; then
      echo ""
      echo "##### PNG Chunk Test"
      for opt in seAl sEAl sEAL seAL teXt ; do
        i=regression/test-unsigned.png
        ka=rsa
	  sf="date3:base64"
	  sfname=${sf/:/_}
	  j=${i/regression/test.dir}
	    out=${j/-unsigned/-signed-local-pngchunk-$opt-$ka-$sfname}
	    echo ""
	    bin/sealtool -v -s -k "test.dir/sign-$ka.key" --options "$opt" --ka "$ka" --dnsfile "test.dir/sign-$ka.dns" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out" "$i"
	    if [ "$?" != "0" ] ; then exit; fi
	    echo ""
	    bin/sealtool -v --ka "$ka" --dnsfile "test.dir/sign-$ka.dns" "$out"
	    if [ "$?" != "0" ] ; then exit; fi
      done
    fi
  fi
fi

### Append
if [ $ISONLYMANUAL == 0 ] ; then
  if [ $ISLOCAL == 1 ] && [ $ISAPPEND == 1 ] ; then
    echo ""
    echo "##### Append Test"
    for ka in ec ; do
      for sf in 'date3:hex' ; do
	sfname=${sf/:/_}
	for i in regression/test-unsigned*"$FMT" ; do
	  ext=${i##*.}
	  if [ "$ext" == "zip" ] ; then continue ; fi # unsupported right now

	  j=${i/regression/test.dir}
	  out1=${j/-unsigned/-signed-local-append1-$ka-$sfname}
	  out2=${j/-unsigned/-signed-local-append2-$ka-$sfname}
	  out3=${j/-unsigned/-signed-local-append3-$ka-$sfname}
	  # create but leave open for appending
	  echo ""
	  bin/sealtool -v -s -k "test.dir/sign-$ka.key" --options append --ka "$ka" --dnsfile "test.dir/sign-$ka.dns" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out1" "$i"
	  if [ "$?" != "0" ] ; then exit; fi
	  echo ""
	  bin/sealtool -v --ka "$ka" --dnsfile "test.dir/sign-$ka.dns" "$out1"
	  if [ "$?" != "0" ] ; then exit; fi
	  # append
	  echo ""
	  bin/sealtool -v -s -k "test.dir/sign-$ka.key" --options append --ka "$ka" --dnsfile "test.dir/sign-$ka.dns" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out2" "$out1"
	  if [ "$?" != "0" ] ; then exit; fi
	  echo ""
	  bin/sealtool -v --ka "$ka" --dnsfile "test.dir/sign-$ka.dns" "$out2"
	  # finalize
	  echo ""
	  bin/sealtool -v -s -k "test.dir/sign-$ka.key" --ka "$ka" --dnsfile "test.dir/sign-$ka.dns" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out3" "$out2"
	  if [ "$?" != "0" ] ; then exit; fi
	  echo ""
	  bin/sealtool -v --ka "$ka" --dnsfile "test.dir/sign-$ka.dns" "$out3"
	  if [ "$?" != "0" ] ; then exit; fi
	done
      done #sf
    done # ka
  fi
fi

### Try manual fields
if [ "$FMT" == "" ] || [ "$FMT" == ".jpg" ] ; then
  if [ $ISREMOTE == 1 ] && [ $ISFINAL == 1 ] ; then
    echo ""
    echo "##### Manual Test"
    echo ""
    echo "#### Non-standard JPEG comment"
    ./SignManual.sh -Comment test.dir/test-signed-remote-manual-comment.jpg
    if [ "$?" != "0" ] ; then exit; fi

    echo ""
    echo "#### EXIF"
    ./SignManual.sh -EXIF:seal test.dir/test-signed-remote-manual-exif.jpg
    if [ "$?" != "0" ] ; then exit; fi

    echo ""
    echo "#### XMP"
    ./SignManual.sh -XMP:seal test.dir/test-signed-remote-manual-xmp.jpg
    if [ "$?" != "0" ] ; then exit; fi
  fi
fi

