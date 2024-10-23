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
|JPEG  |SEAL blocks.|All other applicaton blocks.|
|PNG   |SEAL or text chunks.|All other text chunks.|
|WEBP  |No, but coming soon.|No, but coming soon.|
|HEIC  |No, but coming soon.|No, but coming soon.|
|TIFF  |No, but coming soon.|No, but coming soon.|
|DICOM |No, but coming soon.|No, but coming soon.|
|EXIF  |No.|No, but coming soon.|
|XMP   |No.|Reads as a text field.|
|FAX   |No.|No. Seriously, just no.|
|GIF   |TBD|TBD|
|BMP   |No (no metadata support)|No (no metadata support)|

|Audio Format|Write Support|Read Support|
|------|-------------|------------|
|MP3   |No, but coming soon.|No, but coming soon.|
|MKA   |No, but coming soon.|No, but coming soon.|
|WAV   |No, but coming soon.|No, but coming soon.|

|Video Format|Write Support|Read Support|
|------|-------------|------------|
|MP4  |No, but coming soon.|No, but coming soon.|
|3GP  |No, but coming soon.|No, but coming soon.|
|HEIF  |No, but coming soon.|No, but coming soon.|
|Quicktime  |No, but coming soon.|No, but coming soon.|
|AVI   |No, but coming soon.|No, but coming soon.|
|WEBM  |No, but coming soon.|No, but coming soon.|
|MKV   |No, but coming soon.|No, but coming soon.|

|Documentation Format|Write Support|Read Support|
|------|-------------|------------|
|OpenDocument (docx, pptx, etc.)|No, but coming soon.|No, but coming soon.|
|HTML |No, but coming soon.|No, but coming soon.|
|Plain Text |No, but coming soon.|No, but coming soon.|

