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
|HEIC  |Coming soon.|Coming soon.|
|TIFF  |Coming soon.|Coming soon.|
|DICOM |Coming soon.|Coming soon.|
|EXIF  |No.|Coming soon.|
|XMP   |No.|Reads as a text field.|
|GIF   |TBD|TBD|
|BMP   |No (no metadata support)|No (no metadata support)|
|FAX   |No.|No. Seriously, just no.|

|Audio Format|Write Support|Read Support|
|------|-------------|------------|
|MP3   |Coming soon.|Coming soon.|
|MKA   |SEAL blocks|All SEAL blocks.|
|WAV   |SEAL blocks|All SEAL, XMP, and info blocks.|

|Video Format|Write Support|Read Support|
|------|-------------|------------|
|MP4   |Coming soon.|Coming soon.|
|3GP   |Coming soon.|Coming soon.|
|HEIF  |Coming soon.|Coming soon.|
|Quicktime  |Coming soon.|Coming soon.|
|AVI   |SEAL blocks|All SEAL, XMP, and info blocks.|
|WEBM  |SEAL blocks|All SEAL blocks.|
|MKV   |SEAL blocks|All SEAL blocks.|

|Documentation Format|Write Support|Read Support|
|------|-------------|------------|
|OpenDocument (docx, pptx, etc.)|Coming soon.|Coming soon.|
|PDF |Coming soon.|Coming soon.|
|HTML |Coming soon.|Coming soon.|
|Plain Text |Coming soon.|Coming soon.|

`sealtool` will only parse containers if it recognizing the file format.

|Container Formats|Write Support|Read Support|About|
|------|-------------|------------|-----|
|EXIF |TBD |Coming soon.|EXIF is a standard format for storing metadata. It is often found in JPEG, PNG, and a few other file formats.
|XMP |TBD |Yes, treated as text|XMP is a standard text-based format for storing metadata. It may appear in a wide range of files.
|RIFF |SEAL Blocks |All SEAL, XMP, and info blocks.|The Resource Interchange File Format (RIFF) is a containing file format used by WAV, AVI, and a few other (less common) file formats.|
|ISO-BMFF |Coming soon. |Coming soon.|ISO's Base Media File Format (BMFF, also called ISO-14496) is a containing file for
mat used MP4, 3GP, HEIF, HEIC, AVIF, and other common media files.|
|Matroska |SEAL Blocks |All SEAL.|Matroska is a flexible container format used by WebM, MKV (video), and MKA (audio).|
|ZIP |Coming soon. |Coming soon.|ZIP is an archive container that can hold multiple files. The OpenDocument formats use ZIP.|

Want other formats? Let us know!

