# SEAL-C
SEAL is a Secure Evidence Attribution Label. It permits signing media for attribution. The specifications are at: https://github.com/hackerfactor/SEAL

This is an implementation of SEAL in C.

This code:
1. Generates keys. The private key should be kept private. The public key is ready to be uploaded to your DNS TXT record.
2. Sign files using the private key. It also supports using a remote signing service.
3. Validating signatures. This only requires DNS access. For testing/debugging, you can specify the public key DNS TXT file that you generated.

See the [BUILD](BUILD.md) file for compiling and usage.

This code currently supports static-files only. It does not support streaming data. (The SEAL protocol supports streaming data, but this implementation does not (yet).)

|Image Format|Write Support|Read Support|
|------|-------------|------------|
|JPEG  |SEAL blocks.|All SEAL and applicaton blocks.|
|PNG   |SEAL or text chunks.|All SEAL and text chunks.|
|WEBP  |SEAL blocks|All SEAL, XMP, and informational (INFO) blocks.|
|HEIC  |SEAL blocks|SEAL blocks, or any top-level XML or info.|
|AVIF  |SEAL blocks|SEAL blocks, or any top-level XML or info.|
|PNM/PPM/PGM|SEAL in comments|SEAL in comments.|
|EXIF  |See [Manual Signing](#manualsigning)|Coming soon.|
|XMP   |See [Manual Signing](#manualsigning)|Reads as a text field.|
|TIFF  |Coming soon.|Coming soon.|
|DICOM |Coming soon.|Coming soon.|
|GIF   |TBD|TBD|
|BMP   |No (no metadata support)|No (no metadata support)|
|FAX   |No.|No. Seriously, just no.|

|Audio Format|Write Support|Read Support|
|------|-------------|------------|
|AVIF  |SEAL blocks|SEAL blocks, or any top-level XML or info.|
|WAV   |SEAL blocks|All SEAL, XMP, and info blocks.|
|MKA   |SEAL blocks|All SEAL blocks.|
|MP3   |Coming soon.|Coming soon.|

|Video Format|Write Support|Read Support|
|------|-------------|------------|
|MP4   |SEAL blocks|SEAL blocks, or any top-level XML or info.|
|3GP   |SEAL blocks|SEAL blocks, or any top-level XML or info.|
|AVI   |SEAL blocks|All SEAL, XMP, and info blocks.|
|AVIF  |SEAL blocks|SEAL blocks, or any top-level XML or info.|
|HEIF  |SEAL blocks|SEAL blocks, or any top-level XML or info.|
|HEVC  |SEAL blocks|SEAL blocks, or any top-level XML or info.|
|Quicktime |SEAL blocks|SEAL blocks, or any top-level XML or info.|
|WEBM  |SEAL blocks|All SEAL blocks.|
|MKV   |SEAL blocks|All SEAL blocks.|

|Documentation Format|Write Support|Read Support|
|------|-------------|------------|
|OpenDocument (docx, pptx, etc.)|Coming soon.|Coming soon.|
|PDF |SEAL records in PDF comments|SEAL records in PDF comments|
|HTML |Coming soon.|Coming soon.|
|Plain Text |Coming soon.|Coming soon.|

`sealtool` will only parse containers if it recognizing the file format.

|Container Formats|Write Support|Read Support|About|
|------|-------------|------------|-----|
|EXIF |TBD |Coming soon.|EXIF is a standard format for storing metadata. It is often found in JPEG, PNG, and a few other file formats.
|XMP |See [Manual Signing](#manualsigning)|Yes, treated as text|XMP is a standard text-based format for storing metadata. It may appear in a wide range of files.
|RIFF |SEAL blocks |All SEAL, XMP, and info blocks.|The Resource Interchange File Format (RIFF) is a container format used by WAV, AVI, and a few other (less common) media files.|
|ISP-BMFF |SEAL blocks|SEAL blocks, or any top-level XML or info.|ISO's Base Media File Format (BMFF, also called ISO-14496) is a container format used MP4, 3GP, HEIF, HEIC, AVIF, and other common media files.|
|Matroska |SEAL blocks |All SEAL blocks.|Matroska is a flexible container format used by WebM, MKV (video), and MKA (audio).|
|ZIP |Coming soon. |Coming soon.|ZIP is an archive container that can hold multiple files. The OpenDocument formats use ZIP.|

Want other formats? Let us know!

## <a name='manualsigning'></a>Manual Signing
`sealtool` provides a manual signing option. This is where it generates the SEAL record, but it is up to you to insert the record into the file.

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

