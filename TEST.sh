#!/bin/bash

rm -rf test
mkdir test

FMT=""
if [ "$1" != "" ] ; then
  FMT=".$1"
fi

echo "##### Local Key Generation Test"
for ka in rsa ec ; do
  # generate keys
  bin/sealtool -g --ka "$ka" -D "test/sign-$ka.dns" -k "test/sign-$ka.key" --genpass ''
done # ka

if [ 1 == 1 ] ; then
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
    for i in regression/test-unsigned*"$FMT" ; do
      j=${i/regression/test}
      out=${j/-unsigned/-signed-local-$da-$ka-$sfname}
      bin/sealtool -s -k "test/sign-$ka.key" --ka "$ka" --da "$da" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out" "$i"
    done

    # Verify local signing
    echo ""
    echo "#### Verify Local $da $ka $sf"
    bin/sealtool --ka "$ka" --dnsfile "test/sign-$ka.dns" test/test-*local-$da-$ka-$sfname*

    # Test with remote signing
    echo ""
    echo "#### Remote Signing $da $ka $sf"
    for i in regression/test-unsigned*"$FMT" ; do
      j=${i/regression/test}
      out=${j/-unsigned/-signed-remote-$da-$ka-$sfname}
      bin/sealtool -S --da "$da" --ka "$ka" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out" "$i"
    done

    # Verify remote signing
    echo ""
    echo "#### Verify Remote $da $ka $sf"
    bin/sealtool test/test-*remote-$da-$ka-$sfname*
  done #sf
done # ka
done # da
fi

### PNG options
if [ "$FMT" == "" ] || [ "$FMT" == ".png" ] ; then
echo ""
echo "##### PNG Chunk Test"
for opt in seAl sEAl sEAL seAL teXt ; do
  i=regression/test-unsigned.png
  ka=rsa
    sf="date3:base64"
    sfname=${sf/:/_}
    j=${i/regression/test}
      out=${j/-unsigned/-signed-local-pngchunk-$opt-$ka-$sfname}
      echo ""
      bin/sealtool -v -s -k "test/sign-$ka.key" --options "$opt" --ka "$ka" --dnsfile "test/sign-$ka.dns" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out" "$i"
      echo ""
      bin/sealtool -v --ka "$ka" --dnsfile "test/sign-$ka.dns" "$out"
done
fi

### Append
if [ 1 == 1 ] ; then
echo ""
echo "##### Append Test"
for ka in ec ; do
  for sf in 'date3:hex' ; do
    sfname=${sf/:/_}
    for i in regression/test-unsigned*"$FMT" ; do
      j=${i/regression/test}
      out1=${j/-unsigned/-signed-local-append1-$ka-$sfname}
      out2=${j/-unsigned/-signed-local-append2-$ka-$sfname}
      out3=${j/-unsigned/-signed-local-append3-$ka-$sfname}
      # create but leave open for appending
      echo ""
      bin/sealtool -v -s -k "test/sign-$ka.key" --options append --ka "$ka" --dnsfile "test/sign-$ka.dns" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out1" "$i"
      echo ""
      bin/sealtool -v --ka "$ka" --dnsfile "test/sign-$ka.dns" "$out1"
      # append
      echo ""
      bin/sealtool -v -s -k "test/sign-$ka.key" --options append --ka "$ka" --dnsfile "test/sign-$ka.dns" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out2" "$out1"
      echo ""
      bin/sealtool -v --ka "$ka" --dnsfile "test/sign-$ka.dns" "$out2"
      # finalize
      echo ""
      bin/sealtool -v -s -k "test/sign-$ka.key" --ka "$ka" --dnsfile "test/sign-$ka.dns" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out3" "$out2"
      echo ""
      bin/sealtool -v --ka "$ka" --dnsfile "test/sign-$ka.dns" "$out3"
    done
  done #sf
done # ka
fi

### Try manual fields
if [ "$FMT" == "" ] || [ "$FMT" == ".jpg" ] ; then
echo ""
echo "##### Manual Test"
echo ""
echo "#### Non-standard JPEG comment"
./SignManual.sh -Comment test/test-signed-local-manual-comment.jpg

echo ""
echo "#### EXIF"
./SignManual.sh -EXIF:seal test/test-signed-local-manual-exif.jpg

echo ""
echo "#### XMP"
./SignManual.sh -XMP:seal test/test-signed-local-manual-xmp.jpg
fi

