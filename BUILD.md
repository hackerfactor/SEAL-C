# Building the code
SEAL command-line tool (sealtool).

This code is written in C (but I compile it with g++ because it has more error messages).

## Requirements
1. g++ version 9.x
2. OpenSSL version 3.x. (If you run `openssl --version` and it says 1.x, then it won't work.) You need the developer libraries installed. (For my system, I downloaded the latest version directly from [OpenSSL](https://openssl-library.org/source/index.html) and compiled it. I did this because the default package provided by Debian and Ubuntu is far from the most recent version.))
3. libcurl (developer libraries). On Ubuntu, I use: `apt install libcurl4-openssl-dev`
4. `make`

For debugging:
5. Electric Fence (libefence): `apt install electric-fence`
6. Valgrind: `apt install valgrind`

## Build
1. Clone this repository
2. Run `make`. This will build into bin/sealtool

## Local Signing
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

## Remote Signing
1. Create an account on a signing service, such as signmydata.com. It will assign you an ID, URL for signing, and API key.

2. Sign using the capital `-S` parameter. Be sure to supply your ID, domain, API key, and API url. For example:
```
sealtool -S -D signmydata.com --id 12345 --apiurl 'https://signmydata.com/?sign' --apikey 'abcd1234' -o file-seal.jpg file.jpg
```

3. Check the signature:
```
sealtool file-seal.jpg
```

If you don't want to repeatedly enter the long set of command-line parameters, you can use a configuration file: $HOME/.seal.cfg
```
# Remote signing options (for use with -S)
domain=signmydata.com
digestalg=sha256
keyalg=rsa
kv=1
sf=date:hex
apiurl=https://signmydata.com/?sign
apikey=abcd1234
id=12345
outfile=./%b-seal%e
```
Then you can use:
```
sealtool -S file.jpg
```

## <a name='manualsigning'></a>Manual Signing
`sealtool` can sign many file formats. However, what if you want to sign a file using a format that it doesn't support? (E.g., it can read XMP data but it cannot write XMP data.) The program includes a manual signing option. This is where it generates the SEAL record, but it is up to you to insert the record into the file.

1. Generate the initial SEAL record template. This uses the -m or -M parameters with no value after it. Use -m for local signing and -M for remote signing. For example:
```
$ sealtool -M '' --apiurl *url* --apikey *key* --id 12345
<seal seal="1" kv="1" ka="rsa" da="sha256" sf="date:hex" id="12345" b="F~S,s~f" d="signmydata.com" s="22222222222222:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefab"/>
```
This returns a template that has the correct formatting and spacing for inserting into XMP, EXIF, or some other metadata field. If necessary, you can change the `b=` parameter to match your file format.

2. Insert the template into your file.

3. Verify that `sealtool` sees the template. It should report that the signature is invalid. Use the `-v` parameter to see the computed digest values.
```
$ bin/sealtool -v test.jpg
[test.jpg]
 SEAL record #1 is invalid: signature mismatch.
  Digest: 08a69e78b54266759cfdf45e5a4a89e60dfea5ecf27bd6b4db83b92294dc2b9c
  Double Digest: 03184ecbcaa21fc68bc6c7a033326380ce6dd9579fceb9804e87f9a2c2188431
```
  - The "Digest" refers to the computed byte range (`b=`) processed by the digest algorithm (`da=`).
  - The "Double Digest" appears if there is a timestamp (`sf=date:hex`) or user identity (`id=`).

4. Use the computed "Digest" (not Double Digest) to recompute the template with the appropriate signature.
```
$ sealtool -M '08a69e78b54266759cfdf45e5a4a89e60dfea5ecf27bd6b4db83b92294dc2b9c' --apiurl *url* --apikey *key* --id 12345
<seal seal="1" kv="1" ka="rsa" da="sha256" sf="date:hex" id="12345" b="F~S,s~f" d="signmydata.com" s="20241109174806:3c809fb0a66f51569e20f05b2d6a97504adff60a8961e35fed8274a555fccee7cbf662bc313963c6510eda86bf965ece38bf66094e46acbf21a1d908b2a3c9c3591f2042a977402dc67d5cd7395cc9a6ccde780c0ddd9a72f135c91bbe7c217b08045c848944440bed7b4e4ea4b061558df0ade7f6a2023cddaeaa1932d16dc05dabf33a901a0ff46fefafa7b74b8d1eb23f59869234f328a34682392e5cae47a9ec6263eb82323e53e8eaf94d2562648485d454dc2b3ec779a13e904a15b80f3ce2e0cd7791aa397ad1b883829deb9e2b9b66fc207db8822119b419f3d7cdbac54fb7902b9e9dba51f4dbdd3c34a85b452f1cee60d87845abe8668fc2e093db"/>
```
This contains the computed signature for your provided digest. You can now replace the placeholder template in your file with this signature.

## Current Status
This is the initial release.
- It supports a wide range of image, audio, video, and document files -- with more being added. All common web formats are supported, including JPEG, PNG, WebP, PDF, and MP4.
- It supports RSA and elliptic curve (EC using prime256v1 and secp256r1).
- Needs an autogen for building the code. (How do I make autogen require openssl 3.x?)

If you see any problems, let me know!

