# Building the code
SEAL command-line tool (sealtool).

This code is written in C (but I compile it with g++ because it has more error messages).

## Requirements
1. g++ version 9.x
2. OpenSSL version 3.x. (If you run `openssl --version` and it says 1.x, then it won't work.) You need the developer libraries installed.
3. libcurl (developer libraries)
4. `make`

For debugging:
5. Electric Fence (libefence)
6. Valgrind

## To Build
1. Clone this repository
2. Run `make`. This will build into bin/sealtool

## To Use
First, generate some keys. For example, to generate RSA keys, use:
  `bin/sealtool -g -K rsa -k seal-rsa.key -D seal-rsa.dns`
This will generate two files:
- seal-rsa.key: Your private key. Don't share this.
- seal-rsa.dns: Your public key, formatted and ready to be put in your DNS TXT field.

Second, sign a picture. I have some regression testing pictures in the regression/ directory.
  `bin/sealtool -s -d example.com -K rsa -k seal-rsa.key regression/test-unsigned.png`
- This says that the public key is in the DNS TXT record for "example.com" and uses RSA encryption.
- You can change the encoding format (e.g., `--sf date3:base64`) and specify a user identifier (e.g., `--id BobNotBill`).
- You can specify whether to allow appending more signature (`-O append`) and whether to use the default PNG sEAl chunk or a text chunk (e.g., `-O append,tEXt`).
- This will create the signed file: `./test-unsigned-seal.png` (It appends "-seal" to the signed filename.)

Finally, you can test the signature. If you have DNS configured, then you can use:
  `bin/sealtool ./test-unsigned-seal.png`
If you don't have DNS configured, then you can test with your public key:
  `bin/sealtool --pubkeyfile ./seal-rsa.dns ./test-unsigned-seal.png`

## Current Status
This is the initial release.
- It only supports PNG right now. Other formats, like JPEG, PPM, MOV, etc. are coming very soon.
- Needs an autogen for building the code. (How do I make autogen require openssl 3.x?)
- It needs automated regression testing.
- RSA works. I haven't tested EC very much. And some EC algorithms (e.g., P-384) are not working for some unknown reason. I need to add more crypto options.

Remember, this is the first release. If you see any problems, let me know!

