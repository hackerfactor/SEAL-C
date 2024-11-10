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
|JPEG  |Yes: SEAL blocks.|Yes: All SEAL and applicaton blocks.|
|PNG   |Yes: SEAL or text chunks.|Yes: All SEAL and text chunks.|
|WEBP  |Yes: SEAL blocks|Yes: All SEAL, XMP, and informational (INFO) blocks.|
|HEIC  |Yes: SEAL blocks|Yes: SEAL blocks, or any top-level XML or info.|
|AVIF  |Yes: SEAL blocks|Yes: SEAL blocks, or any top-level XML or info.|
|PNM/PPM/PGM|Yes: SEAL in comments|Yes: SEAL in comments.|
|EXIF  |Yes: See [Manual Signing](BUILD.md#manualsigning)|Coming soon.|
|XMP   |Yes: See [Manual Signing](BUILD.md#manualsigning)|Yes: Reads as a text field.|
|TIFF  |Coming soon.|Coming soon.|
|DICOM |Coming soon.|Coming soon.|
|GIF   |TBD|TBD|
|BMP   |No (no metadata support)|No (no metadata support)|
|FAX   |No.|No. Seriously, just no.|

|Audio Format|Write Support|Read Support|
|------|-------------|------------|
|AVIF  |Yes: SEAL blocks|Yes: SEAL blocks, or any top-level XML or info.|
|M4A   |Yes: SEAL blocks|Yes: SEAL blocks, or any top-level XML or info.|
|MKA   |Yes: SEAL blocks|Yes: All SEAL blocks.|
|MP3   |Coming soon.|Coming soon.|
|WAV   |Yes: SEAL blocks|Yes: All SEAL, XMP, and info blocks.|

|Video Format|Write Support|Read Support|
|------|-------------|------------|
|MP4   |Yes: SEAL blocks|Yes: SEAL blocks, or any top-level XML or info.|
|3GP   |Yes: SEAL blocks|Yes: SEAL blocks, or any top-level XML or info.|
|AVI   |Yes: SEAL blocks|Yes: All SEAL, XMP, and info blocks.|
|AVIF  |Yes: SEAL blocks|Yes: SEAL blocks, or any top-level XML or info.|
|HEIF  |Yes: SEAL blocks|Yes: SEAL blocks, or any top-level XML or info.|
|HEVC  |Yes: SEAL blocks|Yes: SEAL blocks, or any top-level XML or info.|
|MOV/Quicktime |Yes: SEAL blocks|Yes: SEAL blocks, or any top-level XML or info.|
|WEBM  |Yes: SEAL blocks|Yes: All SEAL blocks.|
|MKV   |Yes: SEAL blocks|Yes: All SEAL blocks.|

|Documentation Format|Write Support|Read Support|
|------|-------------|------------|
|OpenDocument (docx, pptx, etc.)|Coming soon.|Coming soon.|
|PDF |Yes: SEAL records in PDF comments|Yes: SEAL records in PDF comments|
|HTML |Coming soon.|Coming soon.|
|Plain Text |Coming soon.|Coming soon.|

`sealtool` will only parse containers if it recognizing the file format.

|Container Formats|Write Support|Read Support|About|
|------|-------------|------------|-----|
|EXIF |TBD |Coming soon.|EXIF is a standard format for storing metadata. It is often found in JPEG, PNG, and a few other file formats.
|XMP |Yes: See [Manual Signing](BUILD.md#manualsigning)|Yes: Yes, treated as text|XMP is a standard text-based format for storing metadata. It may appear in a wide range of files.
|RIFF |Yes: SEAL blocks |Yes: All SEAL, XMP, and info blocks.|The Resource Interchange File Format (RIFF) is a container format used by WAV, AVI, and a few other (less common) media files.|
|ISP-BMFF |Yes: SEAL blocks|Yes: SEAL blocks, or any top-level XML or info.|ISO's Base Media File Format (BMFF, also called ISO-14496) is a container format used MP4, 3GP, HEIF, HEIC, AVIF, and other common media files.|
|Matroska |Yes: SEAL blocks |Yes: All SEAL blocks.|Matroska is a flexible container format used by WebM, MKV (video), and MKA (audio).|
|ZIP |Coming soon. |Coming soon.|ZIP is an archive container that can hold multiple files. The OpenDocument formats use ZIP.|

Want other formats? Let us know!

