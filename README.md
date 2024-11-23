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
|JPEG  |Yes|Yes|
|PNG   |Yes|Yes|
|GIF   |Yes|Yes|
|WEBP  |Yes|Yes|
|HEIC  |Yes|Yes|
|AVIF  |Yes|Yes|
|PNM/PPM/PGM|Yes|Yes|
|SVG   |Yes|Yes|
|TIFFⁱ  |Yes|Yes|
|DICOM |Coming soon|Coming soon|
|BMP   |No (no metadata support)|No (no metadata support)|
|FAX   |No|No. Seriously, just no.|

ⁱ TIFF includes many camera-raw formats, including Adobe Digital Negative (DNG), Canon CRW and CR2, Hasselblad 3FR, Kodan KDC, Leica RAW, Nikon NEF, Panasonic Raw, and Sony ARW.

|Audio Format|Write Support|Read Support|
|------|-------------|------------|
|AVIF  |Yes|Yes|
|M4A   |Yes|Yes|
|MKA   |Yes|Yes|
|MP3   |Yes|Yes|
|MP3+ID3|Yes|Yes|
|MPEG  |Yes|Yes|
|WAV   |Yes|Yes|

|Video Format|Write Support|Read Support|
|------|-------------|------------|
|MP4   |Yes|Yes|
|3GP   |Yes|Yes|
|AVI   |Yes|Yes|
|AVIF  |Yes|Yes|
|HEIF  |Yes|Yes|
|HEVC  |Yes|Yes|
|DIVX  |Yes|Yes|
|MKV   |Yes|Yes|
|MOV/Quicktime |Yes|Yes|
|MPEG  |Yes|Yes|
|WEBM  |Yes|Yes|

|Documentation Format|Write Support|Read Support|
|------|-------------|------------|
|PDF |Yes|Yes|
|XML|Yes|Yes|
|HTML|Yes|Yes|
|Plain Text|Yes|Yes|
|OpenDocument (docx, pptx, etc.)|Coming soon|Coming soon|

|Container Formats|Write Support|Read Support|About|
|------|-------------|------------|-----|
|EXIF  |Yes: See [Manual Signing](BUILD.md#manualsigning)|Yes: Reads 0xceal and comments|EXIF is a standard format for storing metadata. It is often found in JPEG, PNG, and a few other file formats.
|XMP |Yes: See [Manual Signing](BUILD.md#manualsigning)|Yes: Yes, treated as text|XMP is a standard text-based format for storing metadata. It may appear in a wide range of files.
|RIFF |Yes: SEAL blocks |Yes: All SEAL, XMP, and info blocks.|The Resource Interchange File Format (RIFF) is a container format used by WAV, AVI, and a few other (less common) media files.|
|ISO-BMFF |Yes: SEAL blocks|Yes: SEAL blocks, or any top-level XML or info.|ISO's Base Media File Format (BMFF, also called ISO-14496) is a container format used MP4, 3GP, HEIF, HEIC, AVIF, and other common media files.|
|Matroska |Yes: SEAL blocks |Yes: All SEAL blocks.|Matroska is a flexible container format used by WebM, MKV (video), and MKA (audio).|
|ZIP |Coming soon. |Coming soon.|ZIP is an archive container that can hold multiple files. The OpenDocument formats use ZIP.|

This is *not* every file format that `sealtool` supports! Many formats are based on other formats. (CR2 is based on TIFF, DIVX is based on RIFF, etc.). Similar formats are likely already supported. `sealtool` will only parse files when it recognizing the file format.

Have a format you need that isn't supported? Let us know!

