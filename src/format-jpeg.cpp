/************************************************
 SEAL: implemented in C
 See LICENSE

 Functions for handling JPEG files.

 JPEG is a standard that likes to deviate from its standard.

 Each block begins with a two byte value, like: ffd8
 To identify a block, use:
   if (u16 & 0xffc0) == 0xffc0

 Some blocks have a length after them, but others don't.
   ffd8 :: start of image (no length)
     ffe0 - ffef :: app blocks, includes a 2-byte length
       The length includes itself! Never less than 2!
       The APP name is based on the last nibble:
       ffe0 = APP0, ffe5 = APP5, ffee = APP14, etc.
     ffda :: start of stream (forget nice blocks; just dump data after a short header)
   ffd9 :: end of image (no length)

 What if an app block needs to be longer than 2 bytes (65536 bytes)?
 Just have multple app blocks and they get contatenated.
 Some apps repeat the header in each continuation, while others don't.
 (See, the non-standard standard.)

 For the APP blocks, there should be:
   APPn :: 0xFFEn
   2 byte length, including itself
   Usually a name for the type of APP.
   APP data that matches the length-2

 There shouldn't be anything after the ffd9.
 Except that some blocks, like MakerNotes or APP2's MPF stuff data
 after the end of image because it's easier than writing multiple APP blocks.
 And some formats (ahem, Samsung) likes to include 'trailer' data in a non-JPEG format.

 When scanning for blocks, you cannot just look for the &ffc0 header.
 Why? Because some APP block, like EXIF, may include a JPEG as a thumbnail!
 So how do you scan?
   1. Read the tag. If it's not &ffc0, then skip a byte and try again.
      (It's okay to skip bytes in a jpeg.
   2. If the tag is ffd8 or ffd9, then don't read a length.
   3. For any other tag, read the 2-byte length.
      Assume anything inside the block is data for that block.

 For inserting SEAL:
   - Use APP8.  Why APP8? Nobody else uses it!
     Here's the APP block usage that I've found:
     APP1  = Exif (standard)
     APP1  = XMP or Adobe name-space (standard, but thanks to Adobe, it conflicts with Exif)
     APP1  = PIC (Accusoft Pegasus)
     APP2  = ICC Profile (standard)
     APP2  = Flashpix
     APP2  = MPF
     APP4  = Qualcomm Camera Debug
     APP5  = HPQ
     APP5  = ssuniqueid (Samsung)
     APP6  = MMIMETA (Motorola)
     APP7  = Gena Photo Stamper (Russian AvtoVAZ fraud)
     APP10 = AROT (Apple)
     APP10 = MOTO (Motorola)
     APP11 = JPEG2000 (JN or JPN from Microsoft Designer)
     APP11 = DP2
     APP12 = Ducky (photoshop extension; does not indicate an Adobe product!)
     APP13 = Photoshop 3.0
     APP13 = Adobe_CM
     APP14 = Adobe (does not indicate an Adobe product!)
     APP15 = Text (standard comments)
     APP15 = Q (non-standard debug code)

     See? Nobody uses APP8!
     The text string should be "SEAL\0\0".

   - Insert it as fast as possible, right after the initial FFD8.

   - If you see an MPF record (common, thanks to Apple and Samsung), then
     increment the offsets to the post-ffd9 data by the size of the SEAL data.

   - If you encounter any other blocks with a SEAL record:
     Leave it! The signature will become invalid due to the new signature.
     Optional: Prompt the user if you want to remove it.
     To remove it: don't delete! Just change the name "seal" to "seaL".
     (Why not delete? Believe me, you don't want the headache from trying to
     shrink a JPEG, especially if it's in an XMP record.)

 For decoding:
   - Skip any nested images; they are self-contained.
   - For Exif: Check for any EXIF comment, but don't scan any nested images.
   - Check any other app block.
     If any contain a regex that matches the SEAL record, then use it.
   - When you hit the ffd9, STOP! Anything else is nested.

 ************************************************/
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include "seal.hpp"

/**************************************
 FormatJPEG(): TBD
 **************************************/
uint32_t	FormatJPEG	(uint32_t DataLen, byte *Data)
{
  return(0); // TBD
} /* FormatJPEG() */

