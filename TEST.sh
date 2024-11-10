#!/bin/bash

rm -rf test
mkdir test

for ka in rsa ec ; do
  # generate keys
  bin/sealtool -g --ka "$ka" -D "test/sign-$ka.dns" -k "test/sign-$ka.key" --genpass ''
done # ka

if [ 1 == 1 ] ; then
for ka in rsa ec ; do
  # iterate over signing formats
  for sf in 'hex' 'HEX' 'base64' 'date3:hex' 'date3:HEX' 'date3:base64' ; do
    sfname=${sf/:/_}

    # Test with local signing
    echo ""
    echo "#### Local Signing $ka $sf"
    echo ""
    for i in regression/test-unsigned* ; do
      j=${i/regression/test}
      out=${j/-unsigned/-signed-local-$ka-$sfname}
      bin/sealtool -s -k "test/sign-$ka.key" --ka "$ka" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out" "$i"
    done

    # Verify local signing
    echo ""
    echo "#### Verify Local $ka $sf"
    bin/sealtool --ka "$ka" --dnsfile "test/sign-$ka.dns" test/test-*local-$ka-$sfname*

    # Test with remote signing
    echo ""
    echo "#### Remote Signing $ka $sf"
    for i in regression/test-unsigned* ; do
      j=${i/regression/test}
      out=${j/-unsigned/-signed-remote-$ka-$sfname}
      bin/sealtool -S --ka "$ka" --sf "$sf" -C "Sample Copyright" -c "Sample Comment" -o "$out" "$i"
    done

    # Verify remote signing
    echo ""
    echo "#### Verify Remote $ka $sf"
    bin/sealtool test/test-*remote-$ka-$sfname*
  done #sf
done # ka
fi

### Append
if [ 1 == 1 ] ; then
for ka in ec ; do
  for sf in 'date3:hex' ; do
    sfname=${sf/:/_}
    for i in regression/test-unsigned* ; do
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
if [ 1 == 1 ] ; then
echo ""
echo "#### Non-standard JPEG comment"
./SignManual.sh -Comment test/test-signed-comment.jpg

echo ""
echo "#### EXIF"
./SignManual.sh -EXIF:seal test/test-signed-exif.jpg

echo ""
echo "#### XMP"
./SignManual.sh -XMP:seal test/test-signed-comment.jpg
fi

