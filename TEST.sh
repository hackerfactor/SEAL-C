#!/bin/bash

rm -rf test
mkdir test

for ka in rsa ec ; do
  # generate key
  bin/sealtool -g --ka "$ka" -D "test/sign-$ka.dns" -k "test/sign-$ka.key" --genpass ''

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
    bin/sealtool --ka "$lag" --dnsfile1 "test/sign-$ka.dns" test/test-*local-$ka-$sfname*

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

